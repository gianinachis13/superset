from flask import redirect, flash, request
from flask_appbuilder.security.views import AuthDBView
from flask_appbuilder.security.views import expose
from flask_login import login_user
from superset.security import SupersetSecurityManager
import jwt
import json
from jwt import PyJWKClient
import base64
import requests
import json
import requests


# Function to decode URL-safe base64 encoded strings
def decode(encoded_string: str) -> str:
    try:
        # Decode the URL-safe base64 encoded string
        decoded_bytes = base64.urlsafe_b64decode(encoded_string)
        print("Decoded URL-safe base64 encoded string", decoded_bytes)
        # Convert bytes to string (assuming UTF-8 encoding)
        return decoded_bytes.decode('utf-8')
    except Exception as e:
        flash(f'Base64 decoding error: {str(e)}', 'danger')
        return None

class CustomAuthDBView(AuthDBView):

    @expose('/login/', methods=['GET', 'POST'])
    def login(self):
        print("Login endpoint hit")  # Debugging
        token = request.args.get('token')
        # token = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6Ikg5bmo1QU9Tc3dNcGhnMVNGeDdqYVYtbEI5dyJ9.eyJhdWQiOiJkOWJmNTYwZC01MDJlLTQzNTEtYWRjZi0wOGZjNWQwYzk2NDMiLCJpc3MiOiJodHRwczovL2xvZ2luLm1pY3Jvc29mdG9ubGluZS5jb20vNmU2MDMyODktNWU0Ni00ZTI2LWFjN2MtMDNhODU0MjBhOWE1L3YyLjAiLCJpYXQiOjE3MjcxODI5ODEsIm5iZiI6MTcyNzE4Mjk4MSwiZXhwIjoxNzI3MTg2ODgxLCJhaW8iOiJBVlFBcS84WEFBQUFIaGsrSlVwMWRteFYyTGZKazlJbEpyaWZVMlZEMy8waXVEY0pLcXlBVk1lT1pSSmpXdnAwOWd4dGp0cllGU2pNZHduSDBROC9kWUJyM1h5WXdpbzNjTGJoRjNBTzBxVGlidEdXci9kN3o1ND0iLCJuYW1lIjoiQ0hJUyBHaWFuaW5hLUFsaW5hIiwibm9uY2UiOiI5MmUwMmQ1MS1hOTI2LTQzYzYtYTgyMS03NWY3ZWFhN2ZhMjAiLCJvaWQiOiJmNTEwOWQxNi1iMzY2LTQxZTUtODQ4NS04NWRkZTYzYmYzY2YiLCJwcmVmZXJyZWRfdXNlcm5hbWUiOiJnaWFuaW5hLmNoaXNAdGhhbGVzZ3JvdXAuY29tIiwicmgiOiIwLkFTRUFpVEpnYmtaZUprNnNmQU9vVkNDcHBRMVd2OWt1VUZGRHJjOElfRjBNbGtNaEFERS4iLCJzdWIiOiJrdS1PZTBFX29CM25RSDRIUmRaRmVkelUxUXV2eHc3dUdZYXh3ZlhPUm5vIiwidGlkIjoiNmU2MDMyODktNWU0Ni00ZTI2LWFjN2MtMDNhODU0MjBhOWE1IiwidXRpIjoiX1dLLVpvZ0NERWlVSUZZNVhkTk5BQSIsInZlciI6IjIuMCJ9.ZO6L8I9D3T3P3p9F630quW2B6rfKAuxEY3UYoKz_068H6b1Rtyk5IR-QQkFaKXg4Isb3sBIhrQDbDZaGqKjy5PQO0mggoFjnwMrNrbmwZwuRkGmSQ5IlGRyoDgkAf4ezVHi7SEwAddHvrwxcnzYsxhPLJmdGOwZyJ2ukIHrk7fdlHtYNA1D6QxLoaWFhrgclfniLBwv1wE_JvDcDs4cVjWuvoLVXwfRwPh1ZsFTeZ2NibpbqgjjBXOcuhL-fPgsMcuGwquihgKf28-DY6KXOugicOQV_WEzf881e56a_AtH34OgWszG8DRZga9iJDvO5RK4PP24wabSSKigMyH1i6w'
        dashboard_id = request.args.get('dashboard_id')
        country_str = request.args.get('country_str')
        gbu_str = request.args.get('gbu_str')
        print("country_str",country_str)
        sm = self.appbuilder.sm
        session = sm.get_session

        if not token:
            return super(CustomAuthDBView, self).login()

        try:
            # Decode the JWT token without verification (if you don't need to verify the signature)
            payload = jwt.decode(token, options={"verify_signature": False})

            if payload:
                print("Payload****", payload)
                user_id = payload.get("sub")
                user_role = payload.get("role", "guest")  # Default to guest if role not specified
                json_string = json.dumps(payload)
                data_dict_from_json = json.loads(json_string)
                user_email = data_dict_from_json["preferred_username"]
                # user_email = 'fr@superset.com'
                if user_id:
                    print("U:{token}")
                    print("User id****", user_id)
                    # Fetch user from the database or create a new user if not exists
                    url = "https://dev.emw-mvp.prod-eu2.k8saas.thalesdigital.io/api/v1/emw/user/userInfo"
                    print("Url", url)
                    body = {}
                    headers = {
                    'Authorization': f'Bearer {token}',
                    'Cookie': 'SBSESSIONID=9D25239A653CC72A079E2037EFDDA549'
                    }
                    response = requests.get(url, headers=headers)
                    print("RESPP",response.status_code)
                    if response.status_code == 200:
                        response_json = response.json()
                        print("Response JSON:", json.dumps(response_json, indent=4))
                        user_tgi = response_json['data']['tgi']
                        print("User TGI:", user_tgi)
                        user_roles = response_json['data']['role']
                        print("User roles*:", user_roles)
                    else:
                        print("Error fetching user data:", response.status_code)
                    user = session.query(sm.user_model).filter_by(username=user_roles).first()
              

                                        # if not user:
                                        #     # CURL APELAM API - DACA NU e expirat token-ul? 
                                        #     # call spre EMW API (doar token-ul il trimit) primesc short user, adaug user-ul in baza de date a superset-ului (unul cate unul)
                                        #     # pe prima pagina in filtre selectam doar organizatia user-ului (vor fi vizibile toate tarile), in drill to detail restrictinam tot(vedem doar tara gbu, bl, cc in care sunt eu)
                                        #     # Create a new user if not exists (this is just an example)
                                        #     user = sm.user_model()
                                        #     user.username = 'test2'
                                        #     user.email = user_email
                                        #     user.first_name = 'Test2'
                                        #     user.last_name = 'User2'
                                        #     user.password = 'public'  # Set a default password; this should be hashed in production
                                        #     # sa fie login numai cu token (sa dezactivez pagina de login)
                                        #     user.is_active = True # Check with 0 or 1
                                        #     session.add(user)
                                        #     session.commit()

                                        # # Assign roles based on the token information
                                        # role = session.query(sm.role_model).filter_by(name=user_roles).first()
                                        # print("role", role)
                                        # if not role:
                                        #     # Create a new role if not exists (this is just an example) Ionut imi intoarce numele roluluiu
                                        #     role = sm.role_model(name=user_roles)
                                        #     session.add(role)
                                        #     session.commit()

                                        # # Assign role to user
                                        # user.roles.append(role)
                                        # session.commit()
                
                    login_user(user, remember=False, force=True)

        
                    if dashboard_id:
                        # bl_str = 'VTS'
                        # cc_str= 'LAS/VTS-FR'
                        # return redirect(f"/superset/dashboard/17/?standalone=2&native_filters=(NATIVE_FILTER-DLuziU6vb-LTinkr1pCrF:(__cache:(label:!({country_str}),validateStatus:!f,value:!({country_str})),extraFormData:(filters:!((col:country,op:IN,val:!({country_str})))),filterState:(label:!({country_str}),validateStatus:!f,value:!({country_str})),id:NATIVE_FILTER-DLuziU6vb-LTinkr1pCrF,ownState:()),NATIVE_FILTER-HIwSbdASjRqnj5W1CE0yz_:(__cache:(label:!('{gbu_str}'),validateStatus:!f,value:!('{gbu_str}')),extraFormData:(filters:!((col:gbu,op:IN,val:!('{gbu_str}')))),filterState:(label:!('{gbu_str}'),validateStatus:!f,value:!('{gbu_str}')),id:NATIVE_FILTER-HIwSbdASjRqnj5W1CE0yz_,ownState:()),NATIVE_FILTER-NBvj62O7J:(__cache:(label:!('VTS'),validateStatus:!f,value:!('VTS')),extraFormData:(filters:!((col:bl,op:IN,val:!('VTS')))),filterState:(label:!('VTS'),validateStatus:!f,value:!('VTS')),id:NATIVE_FILTER-NBvj62O7J,ownState:()),NATIVE_FILTER-kIQUyvdyT:(__cache:(label:!('LAS/VTS-FR'),validateStatus:!f,value:!('LAS/VTS-FR')),extraFormData:(filters:!((col:cc,op:IN,val:!('LAS/VTS-FR')))),filterState:(label:!('LAS/VTS-FR'),validateStatus:!f,value:!('LAS/VTS-FR')),id:NATIVE_FILTER-kIQUyvdyT,ownState:()))")
                        return redirect(f"/superset/dashboard/17/?standalone=2&native_filters=(NATIVE_FILTER-IwP3UoITy:(__cache:(label:!('France','Romania'),validateStatus:!f,value:!('France','Romania')),extraFormData:(filters:!((col:country,op:IN,val:!('France','Romania')))),filterState:(label:!('France','Romania'),validateStatus:!f,value:!('France','Romania')),id:NATIVE_FILTER-IwP3UoITy,ownState:()),NATIVE_FILTER-u1GGvp9x5:(__cache:(label:!('LAS'),validateStatus:!f,value:!('LAS')),extraFormData:(filters:!((col:gbu,op:IN,val:!('LAS')))),filterState:(label:!('LAS'),validateStatus:!f,value:!('LAS')),id:NATIVE_FILTER-u1GGvp9x5,ownState:()),NATIVE_FILTER-NBvj62O7J:(__cache:(label:!('VTS'),validateStatus:!f,value:!('VTS')),extraFormData:(filters:!((col:bl,op:IN,val:!('VTS')))),filterState:(label:!('VTS'),validateStatus:!f,value:!('VTS')),id:NATIVE_FILTER-NBvj62O7J,ownState:()),NATIVE_FILTER-kIQUyvdyT:(__cache:(label:!('LAS/VTS-FR'),validateStatus:!f,value:!('LAS/VTS-FR')),extraFormData:(filters:!((col:cc,op:IN,val:!('LAS/VTS-FR')))),filterState:(label:!('LAS/VTS-FR'),validateStatus:!f,value:!('LAS/VTS-FR')),id:NATIVE_FILTER-kIQUyvdyT,ownState:()))")
                    return redirect(self.appbuilder.get_url_for_index)

            flash('Unable to auto login', 'warning')
            return super(CustomAuthDBView, self).login()

        except Exception as e:
            flash(f'Unable to auto login: {str(e)}', 'warning')
            return super(CustomAuthDBView, self).login()

class CustomSecurityManager(SupersetSecurityManager):
    authdbview = CustomAuthDBView

    def __init__(self, appbuilder):
        super(CustomSecurityManager, self).__init__(appbuilder)

def init_app(app):
    # Initialize JWTManager or other app-specific setups if needed
    pass

CUSTOM_SECURITY_MANAGER = CustomSecurityManager
TALISMAN_ENABLED = False
FEATURE_FLAGS = {"DASHBOARD_RBAC": True, "EMBEDDED_SUPERSET": True, "DASHBOARD_FILTERS_EXPERIMENTAL": True,
                 "DASHBOARD_NATIVE_FILTERS": True, "DASHBOARD_CROSS_FILTERS": True, "ENABLE_TEMPLATE_PROCESSING": True, }



# # DEFAULT CONFIGURATION
# # Licensed to the Apache Software Foundation (ASF) under one
# # or more contributor license agreements.  See the NOTICE file
# # distributed with this work for additional information
# # regarding copyright ownership.  The ASF licenses this file
# # to you under the Apache License, Version 2.0 (the
# # "License"); you may not use this file except in compliance
# # with the License.  You may obtain a copy of the License at
# #
# #   http://www.apache.org/licenses/LICENSE-2.0
# #
# # Unless required by applicable law or agreed to in writing,
# # software distributed under the License is distributed on an
# # "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# # KIND, either express or implied.  See the License for the
# # specific language governing permissions and limitations
# # under the License.
# #
# # This file is included in the final Docker image and SHOULD be overridden when
# # deploying the image to prod. Settings configured here are intended for use in local
# # development environments. Also note that superset_config_docker.py is imported
# # as a final step as a means to override "defaults" configured here
# #
# import logging
# import os

# from celery.schedules import crontab
# from flask_caching.backends.filesystemcache import FileSystemCache

# logger = logging.getLogger()

# DATABASE_DIALECT = os.getenv("DATABASE_DIALECT")
# DATABASE_USER = os.getenv("DATABASE_USER")
# DATABASE_PASSWORD = os.getenv("DATABASE_PASSWORD")
# DATABASE_HOST = os.getenv("DATABASE_HOST")
# DATABASE_PORT = os.getenv("DATABASE_PORT")
# DATABASE_DB = os.getenv("DATABASE_DB")

# EXAMPLES_USER = os.getenv("EXAMPLES_USER")
# EXAMPLES_PASSWORD = os.getenv("EXAMPLES_PASSWORD")
# EXAMPLES_HOST = os.getenv("EXAMPLES_HOST")
# EXAMPLES_PORT = os.getenv("EXAMPLES_PORT")
# EXAMPLES_DB = os.getenv("EXAMPLES_DB")

# # The SQLAlchemy connection string.
# SQLALCHEMY_DATABASE_URI = (
#     f"{DATABASE_DIALECT}://"
#     f"{DATABASE_USER}:{DATABASE_PASSWORD}@"
#     f"{DATABASE_HOST}:{DATABASE_PORT}/{DATABASE_DB}"
# )

# SQLALCHEMY_EXAMPLES_URI = (
#     f"{DATABASE_DIALECT}://"
#     f"{EXAMPLES_USER}:{EXAMPLES_PASSWORD}@"
#     f"{EXAMPLES_HOST}:{EXAMPLES_PORT}/{EXAMPLES_DB}"
# )

# REDIS_HOST = os.getenv("REDIS_HOST", "redis")
# REDIS_PORT = os.getenv("REDIS_PORT", "6379")
# REDIS_CELERY_DB = os.getenv("REDIS_CELERY_DB", "0")
# REDIS_RESULTS_DB = os.getenv("REDIS_RESULTS_DB", "1")

# RESULTS_BACKEND = FileSystemCache("/app/superset_home/sqllab")

# CACHE_CONFIG = {
#     "CACHE_TYPE": "RedisCache",
#     "CACHE_DEFAULT_TIMEOUT": 300,
#     "CACHE_KEY_PREFIX": "superset_",
#     "CACHE_REDIS_HOST": REDIS_HOST,
#     "CACHE_REDIS_PORT": REDIS_PORT,
#     "CACHE_REDIS_DB": REDIS_RESULTS_DB,
# }
# DATA_CACHE_CONFIG = CACHE_CONFIG


# class CeleryConfig:
#     broker_url = f"redis://{REDIS_HOST}:{REDIS_PORT}/{REDIS_CELERY_DB}"
#     imports = ("superset.sql_lab",)
#     result_backend = f"redis://{REDIS_HOST}:{REDIS_PORT}/{REDIS_RESULTS_DB}"
#     worker_prefetch_multiplier = 1
#     task_acks_late = False
#     beat_schedule = {
#         "reports.scheduler": {
#             "task": "reports.scheduler",
#             "schedule": crontab(minute="*", hour="*"),
#         },
#         "reports.prune_log": {
#             "task": "reports.prune_log",
#             "schedule": crontab(minute=10, hour=0),
#         },
#     }


# CELERY_CONFIG = CeleryConfig

# FEATURE_FLAGS = {"ALERT_REPORTS": True}
# ALERT_REPORTS_NOTIFICATION_DRY_RUN = True
# WEBDRIVER_BASEURL = "http://superset:8088/"  # When using docker compose baseurl should be http://superset_app:8088/
# # The base URL for the email report hyperlinks.
# WEBDRIVER_BASEURL_USER_FRIENDLY = WEBDRIVER_BASEURL
# SQLLAB_CTAS_NO_LIMIT = True

# #
# # Optionally import superset_config_docker.py (which will have been included on
# # the PYTHONPATH) in order to allow for local settings to be overridden
# #
# try:
#     import superset_config_docker
#     from superset_config_docker import *  # noqa

#     logger.info(
#         f"Loaded your Docker configuration at " f"[{superset_config_docker.__file__}]"
#     )
# except ImportError:
#     logger.info("Using default Docker config...")