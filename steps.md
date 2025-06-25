# Setup Instructions

1. Go to the Azure portal and register your app in Azure Active Directory.
2. Obtain the Tenant ID from your Azure AD overview page.
3. Configure the Enterprise Application’s SAML settings:
   - Set the Identifier (Entity ID) to your app’s unique URI.
   - Set the Reply URL (Assertion Consumer Service URL) to the Callback URL here.
4. Download the x509 Certificate from Azure and paste its Base64 content here.
5. Click "Save Changes and Reload Site" to apply your settings.
6. Test SAML login by clicking "Login with SAML" on the login page.

