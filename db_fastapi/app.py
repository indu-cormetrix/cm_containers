from fastapi import FastAPI, HTTPException, Depends, Request, status
from fastapi.responses import RedirectResponse, JSONResponse
from fastapi.security import OAuth2PasswordBearer
from keycloak import KeycloakOpenID
from pydantic import BaseModel
import uvicorn
from functools import wraps


app = FastAPI()


KEYCLOAK_SERVER_URL = "http://172.18.0.5:8080/"
KEYCLOAK_REALM = "cormetrix"
KEYCLOAK_CLIENT_ID = "db_api_client"
KEYCLOAK_CLIENT_SECRET = "pmoTRbqod19gUYAgkoWx1jIxgwhwg3zr"
KEYCLOAK_CALLBACK_URI = "http://localhost:8000/callback"
KEYCLOAK_VERIFY_SSL = False  
TOKEN_URL = "http://172.18.0.5:8080/realms/cormetrix/protocol/openid-connect/token"

keycloak_openid = KeycloakOpenID(
    server_url=KEYCLOAK_SERVER_URL,
    client_id=KEYCLOAK_CLIENT_ID,
    realm_name=KEYCLOAK_REALM,
    client_secret_key=KEYCLOAK_CLIENT_SECRET,
    verify=KEYCLOAK_VERIFY_SSL
)

oauth2_scheme = OAuth2PasswordBearer(tokenUrl=TOKEN_URL, scopes={})

class UserCreds(BaseModel):
    username: str
    password: str

class TokenResponse(BaseModel):
    token: str
    data: dict

class User(BaseModel):
    name: str
    preferred_username: str
    given_name: str
    family_name: str
    email: str
    address: dict

def check_permission(permission: list):
    def dependency(token_data: TokenResponse = Depends(verify_token)):
        res_permission = keycloak_openid.has_uma_access(token_data.token, permission)
        if res_permission.is_authorized:
            return
        else:
            raise HTTPException(status.HTTP_403_FORBIDDEN, "You are not allowed to access this resource")
    return Depends(dependency)


def verify_token(token: str = Depends(oauth2_scheme)):
    """
    Verify the JWT access token.
    """

    try:
        payload = keycloak_openid.decode_token(token)
        token_data = TokenResponse(token=token, data=payload)

        if token_data.data.get("iss") != f"{KEYCLOAK_SERVER_URL}realms/{KEYCLOAK_REALM}":
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid issuer"
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
            password=creds.password,
            username=creds.username
        )
        return JSONResponse({
            **token_response
        })
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))



@app.get("/users/view")
async def user_detail(token_data: TokenResponse = Depends(verify_token), access = check_permission(permission=["users#read"])):
    """
    This can only accessed by the user with read access
    """
    # keycloak_openid.userinfo(token_data.token)
    try:
        return {"message": "user details", "user_info": User(**token_data.data)}
    except Exception as e:
        raise HTTPException(status_code=500, detail="Invalid or expired token")
    

@app.post("/users/edit")
async def edit_user(token_data: TokenResponse = Depends(verify_token), access = check_permission(permission=["users#write"])):
    """
    This can only accessed by the user with edit access
    """
    try:
        return {"message": "user details", "user_info": User(**token_data.data)}
    except Exception as e:
        raise HTTPException(status_code=500, detail="Invalid or expired token")


if __name__ == "__main__":
   uvicorn.run("app:app", host="0.0.0.0", port=8000, reload=True)




# @app.get("/login")
# async def login():
#     """
#     Redirect the user to Keycloak for login.
#     """
#     authorization_url = keycloak_openid.auth_url(
#         redirect_uri=KEYCLOAK_CALLBACK_URI
#     )
#     return RedirectResponse(authorization_url)


# @app.get("/callback")
# async def callback(request: Request):
#     """
#     Handle the callback from Keycloak. This endpoint receives the authorization code,
#     exchanges it for an access token, and displays the token.
#     """
#     query_params = request.query_params
#     code = query_params.get("code")
    
#     if not code:
#         raise HTTPException(status_code=400, detail="Authorization code not provided")
    
#     try:
#         token_response = keycloak_openid.token(
#             grant_type="authorization_code",
#             code=code,
#             redirect_uri=KEYCLOAK_CALLBACK_URI
#         )

#         return JSONResponse({
#             **token_response
#         })
    
#     except Exception as e:
#         raise HTTPException(status_code=500, detail=str(e))
