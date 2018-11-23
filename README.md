Flower oAuth Azure
------------------


Microsoft Azure login handler for [Flower](https://flower.readthedocs.io/en/latest/)

Flower provides internal support for Google and GitHub OAuth authentication, this package enable 
similar functionality for [Microsoft Azure](https://portal.azure.com/)


## Quick start

    pip install flower-oauth-azure
    

Azure OAuth 2.0 authentication is enabled using the `--auth`, `--oauth2_key`, `--oauth2_secret` and `--oauth2_redirect_uri` options,
to set the Azure tenant `FLOWER_OAUTH2_TENANT` environment variable must be set.

`--auth` is a regular expression, for granting access only to the specified email pattern. 
`–-oauth2_key` and `–-oauth2_secret` are your credentials from your Azure Account. 
`–-oauth2_redirect_uri` is there to specify what is the redirect_uri associated to you key and secret


For instance, if you want to grant access to me@saxix.onmicrosoft.com and you@saxix.onmicrosoft.com:

    $ export FLOWER_OAUTH2_TENANT=saxix.onmicrosoft.com    
    $ celery flower --auth_provider=flower_oauth_azure.tenant.AzureTenantLoginHandler \
                    --auth="me@saxix.onmicrosoft.com|you@saxix.onmicrosoft.com" \
                    --oauth2_key=... \
                    --oauth2_secret=... 
                    --oauth2_redirect_uri=http://flower.example.com/login

Alternatively you can set environment variables instead of command line arguments:

    $ export FLOWER_OAUTH2_KEY=...
    $ export FLOWER_OAUTH2_SECRET=...
    $ export FLOWER_OAUTH2_TENANT=saxix.onmicrosoft.com
    $ export FLOWER_AUTH=.*@saxix\.onmicrosoft\.com
    $ export FLOWER_AUTH_PROVIDER=flower_oauth_azure.tenant.AzureTenantLoginHandler
    $ export FLOWER_OAUTH2_REDIRECT_URI=http://flower.example.com/login
    $ celery flower
