# FROM quay.io/keycloak/keycloak:latest

# ENV KC_DB=postgres
# ENV KC_DB_URL=jdbc:postgresql://cormetrix_postgres/keycloak
# ENV KC_DB_USERNAME=cormetrix
# ENV KC_DB_PASSWORD=cormetrix123
# ENV KC_HOSTNAME=localhost
# ENV KC_BOOTSTRAP_ADMIN_USERNAME=admin
# ENV KC_BOOTSTRAP_ADMIN_PASSWORD=admin

FROM quay.io/keycloak/keycloak:latest
# COPY --from=builder /opt/keycloak/ /opt/keycloak/

# # change these values to point to a running postgres instance
# ENV KC_DB="postgres"
# ENV KC_DB_URL=jdbc:postgresql://cormetrix_postgres/keycloak
# ENV KC_DB_USERNAME=cormetrix
# ENV KC_DB_PASSWORD=cormetrix123
# ENV KC_HOSTNAME=localhost
# ENV KC_BOOTSTRAP_ADMIN_USERNAME=admin
# ENV KC_BOOTSTRAP_ADMIN_PASSWORD=admin

# ENTRYPOINT ["/opt/keycloak/bin/kc.sh"]