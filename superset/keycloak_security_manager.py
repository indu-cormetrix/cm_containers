from flask_appbuilder.security.manager import AUTH_OID
from superset.security import SupersetSecurityManager
from flask_oidc import OpenIDConnect
from flask_appbuilder.security.views import AuthOIDView
from flask_login import login_user
from urllib.parse import quote
from flask_appbuilder.views import ModelView, SimpleFormView, expose
from flask import (
    redirect,
    request
)
import logging

dashboard_role_pvms = [
    ("can_read", "Chart"),
    ("can_read", "Dashboard"),
    ("can_recent_activity","Log"),
    ("can_read","DashboardFilterStateRestApi"),
    ("can_write","DashboardFilterStateRestApi"),
    ("can_dashboard","Superset")
]

class OIDCSecurityManager(SupersetSecurityManager):

    def __init__(self, appbuilder):
        super(OIDCSecurityManager, self).__init__(appbuilder)
        if self.auth_type == AUTH_OID:
            self.oid = OpenIDConnect(self.appbuilder.get_app)
        self.authoidview = AuthOIDCView

        dashboard_role = self.add_role("Dashboard")
        for (action, model) in dashboard_role_pvms:
            pvm = self.find_permission_view_menu(action, model)
            self.add_permission_role(dashboard_role, pvm)

class AuthOIDCView(AuthOIDView):

    @expose('/login/', methods=['GET', 'POST'])
    def login(self, flag=True):
        sm = self.appbuilder.sm
        oidc = sm.oid

        @self.appbuilder.sm.oid.require_login
        def handle_login():
            user = sm.auth_user_oid(oidc.user_getfield('email'))
            AUTH_ROLES_MAPPING = {
                "superset_admin":"Admin",
                "superset_gamma":"Gamma",
                "superset_alpha":"Alpha",
                "superset_sql_lab":"sql_lab",
                "superset_public":"Public",
                "superset_dashboard":"Dashboard"
            }
            user_role = "Gamma"
            roles = oidc.user_getfield('roles')
            logging.info(f"\n--------------Roles {roles}-------------\n")
            if roles:
                for role in roles:
                    fetched_role = AUTH_ROLES_MAPPING.get(role)
                    if fetched_role:
                        user_role = fetched_role
                        break
            logging.info(f"\n------------User Role is {user_role}--------------\n")
            if user is None:
                info = oidc.user_getinfo(['preferred_username', 'given_name', 'family_name', 'email','roles'])
                print(f"\n\n\nuser info:{info}\n\n\n")
                user = sm.add_user(info.get('preferred_username'), info.get('given_name'), info.get('family_name'),
                                   info.get('email'), sm.find_role(user_role))

            login_user(user, remember=False)
            return redirect(self.appbuilder.get_url_for_index)

        return handle_login()

    @expose('/logout/', methods=['GET', 'POST'])
    def logout(self):
        oidc = self.appbuilder.sm.oid

        oidc.logout()
        super(AuthOIDCView, self).logout()
        redirect_url = request.url_root.strip('/') + self.appbuilder.get_url_for_login

        return redirect(
            oidc.client_secrets.get('issuer') + '/protocol/openid-connect/logout?redirect_uri=' + quote(redirect_url))