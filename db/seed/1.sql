CREATE USER keycloak WITH PASSWORD 'keycloak';

CREATE DATABASE keycloak OWNER keycloak;

GRANT ALL PRIVILEGES ON DATABASE keycloak TO keycloak;


CREATE USER superset WITH PASSWORD 'superset';

CREATE DATABASE superset OWNER superset;

GRANT ALL PRIVILEGES ON DATABASE superset TO superset;
