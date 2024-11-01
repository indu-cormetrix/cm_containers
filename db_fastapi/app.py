from fastapi import FastAPI, HTTPException, Depends, Request, status
from fastapi.responses import RedirectResponse, JSONResponse
from fastapi.security import OAuth2PasswordBearer
from keycloak import KeycloakOpenID
from pydantic import BaseModel
import uvicorn
import json
import requests
from functools import wraps
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Adjust this to restrict to specific origins
    allow_credentials=True,
    allow_methods=["*"],  # Adjust to specify allowed methods
    allow_headers=["*"],  # Adjust to specify allowed headers
)


KEYCLOAK_SERVER_URL = "http://172.18.0.5:8080/"
KEYCLOAK_REALM = "cormetrix"
KEYCLOAK_CLIENT_ID = "db_api_client"
KEYCLOAK_CLIENT_SECRET = "pmoTRbqod19gUYAgkoWx1jIxgwhwg3zr"
KEYCLOAK_CALLBACK_URI = "http://localhost:8000/callback"
KEYCLOAK_VERIFY_SSL = False
TOKEN_URL = "http://172.18.0.5:8080/realms/cormetrix/protocol/openid-connect/token"
superset_url = "http://cormetrix_superset:8088"
# superset_url = "http://localhost:8088"


keycloak_openid = KeycloakOpenID(
    server_url=KEYCLOAK_SERVER_URL,
    client_id=KEYCLOAK_CLIENT_ID,
    realm_name=KEYCLOAK_REALM,
    client_secret_key=KEYCLOAK_CLIENT_SECRET,
    verify=KEYCLOAK_VERIFY_SSL,
)


oauth2_scheme = OAuth2PasswordBearer(tokenUrl=TOKEN_URL, scopes={})


class UserCreds(BaseModel):
    username: str
    password: str


mapping = {
    "admin_user": UserCreds(username="test_user", password="test"),
    "patient_user": UserCreds(username="test_user1", password="test"),
}


class TokenResponse(BaseModel):
    token: str
    data: dict


class User(BaseModel):
    name: str
    preferred_username: str
    given_name: str
    family_name: str
    email: str


def get_access_token(username: str, password: str):
    url = f"{superset_url}/api/v1/security/login"
    payload = {"username": username, "password": password, "provider": "db"}

    try:
        response = requests.post(url, json=payload)

        response.raise_for_status()

        data = response.json()
        access_token = data.get("access_token")
        return access_token
    except requests.exceptions.RequestException as error:
        print("Error fetching access token:", error)


def get_csrf_token(access_token: str):
    url = f"{superset_url}/api/v1/security/csrf_token"

    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {access_token}",
    }

    try:
        response = requests.get(url, headers=headers)

        response.raise_for_status()

        data = response.json()
        return data.get("result")

    except requests.exceptions.RequestException as error:
        print("Error fetching CSRF token:", error)


def fetch_guest_token_from_backend(access_token: str, resource: list, user: dict):
    try:
        csrf_token = get_csrf_token(access_token)
        url = f"{superset_url}/api/v1/security/guest_token"
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {access_token}",
            # 'X-CSRF-Token':csrf_token
        }
        payload = {"user": user, "resources": resource, "rls": []}

        response = requests.post(url, headers=headers, data=json.dumps(payload))

        response.raise_for_status()

        guest_token_data = response.json()
        return guest_token_data.get("token")

    except requests.exceptions.RequestException as error:
        print("Error fetching guest token:", error)
        raise


def get_dashboard(access_token):
    url = f"{superset_url}/api/v1/dashboard/"
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json",
    }
    try:
        response = requests.get(url, headers=headers)

        response.raise_for_status()

        dashboards = response.json().get("result", [])
        # embed_ids = [dashboard['id'] for dashboard in dashboards if 'id' in dashboard]

        return dashboards

    except requests.exceptions.RequestException as error:
        print("Error fetching dashboards:", error)


def check_permission(permission: list):
    def dependency(token_data: TokenResponse = Depends(verify_token)):
        res_permission = keycloak_openid.has_uma_access(token_data.token, permission)
        if res_permission.is_authorized:
            return
        else:
            raise HTTPException(
                status.HTTP_403_FORBIDDEN, "You are not allowed to access this resource"
            )

    return Depends(dependency)


def verify_token(token: str = Depends(oauth2_scheme)):
    """
    Verify the JWT access token.
    """

    try:
        payload = keycloak_openid.decode_token(token)
        token_data = TokenResponse(token=token, data=payload)

        if (
            token_data.data.get("iss")
            != f"{KEYCLOAK_SERVER_URL}realms/{KEYCLOAK_REALM}"
        ):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid issuer"
            )

        return token_data

    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Token verification failed: {str(e)}",
            headers={"WWW-Authenticate": "Bearer"},
        )


@app.post("/login")
async def login(request: Request, creds: UserCreds):
    """
    Handle the callback from Keycloak. This endpoint receives the authorization code,
    exchanges it for an access token, and displays the token.
    """
    try:
        token_response = keycloak_openid.token(
            password=creds.password, username=creds.username
        )
        return JSONResponse({**token_response})

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/users/view")
async def user_detail(
    token_data: TokenResponse = Depends(verify_token),
    access=check_permission(permission=["users#read"]),
):
    """
    This can only accessed by the user with read access
    """
    # keycloak_openid.userinfo(token_data.token)
    try:
        return {"message": "user details", "user_info": User(**token_data.data)}
    except Exception as e:
        raise HTTPException(status_code=500, detail="Invalid or expired token")


@app.post("/users/edit")
async def edit_user(
    token_data: TokenResponse = Depends(verify_token),
    access=check_permission(permission=["users#write"]),
):
    """
    This can only accessed by the user with edit access
    """
    try:
        return {"message": "user details", "user_info": User(**token_data.data)}
    except Exception as e:
        raise HTTPException(status_code=500, detail="Invalid or expired token")


@app.post("/dashboard/token")
async def superset_guest_token(token_data: TokenResponse = Depends(verify_token)):
    try:
        user_data = User(**token_data.data)
        superset_creds: UserCreds = mapping.get(user_data.preferred_username)
        access_token = get_access_token(
            superset_creds.username, superset_creds.password
        )
        if not access_token:
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Check the user creds")
        dashboards = get_dashboard(access_token)
        res = []
        for data in dashboards:
            res.append({"type": "dashboard", "id": str(data.get("id", ""))})
        guest_user_detail = {
            "username": user_data.preferred_username,
            "first_name": user_data.given_name,
            "last_name": user_data.family_name,
        }

        guest_token = fetch_guest_token_from_backend(
            access_token, res, guest_user_detail
        )
        return {"guest_token": guest_token}
    except HTTPException as e:
        raise
    except Exception as er:
        print(er)
        raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, str(er))


if __name__ == "__main__":
    uvicorn.run("app:app", host="0.0.0.0", port=8000, reload=True)
