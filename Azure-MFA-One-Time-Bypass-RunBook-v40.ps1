#Params Function to check

param(

    [Parameter(Mandatory,Helpmessage="This is a helpMessage for UPN")]
        [String] $User,


    [Parameter()]
        [int32] $Timer = 0,

    [Parameter()]
        [string]$AppID = $Null
       

)



##Remove-Variable * -Force -ErrorAction SilentlyContinue
##cls


$tenant = "asvk.onmicrosoft.com"
$resource = "https://graph.microsoft.com/"
$authUrl = "https://login.microsoftonline.com/$tenant"
$endresult = $Null
$endresult = @()
$Output1 = @()
$result = $Null
$result1 = $Null
$InFinal = $False                                                                         ############# We are using this temp parameter to decide in the end if a CA policy has to be in the resultant #########################
$endcheck = $False                                                                        ############# This parameter to cut short the loop and come out to check other policies, by default we set this to False ##############
$TemplateId = $Null                                                                       ############# Used to convert User Role IDs to Role Template IDs which CA policies use ########################
$UserRoleTemplateIDs = @()                                                                ############# Array containing all the Role Template IDs the user is assigned to/part of##############################################
$ErrorCatch = $Null
$ErrorCatch2 = $Null
$t = $Null                                                                                ############# Used as a pre requisite to capture Current time of CAP ##############################
#$AppID = $Null                                                                            ############# Used to choose Application Condition ######################




####### READ COMMENTS FROM HERE ############

############################################################################################################################################################
############################################################ Token Initialization ##########################################################################
############################################################################################################################################################

$clientId = "72101369-0976-40e2-a465-bdb003e8af18"                                        #Client ID that you create for your tenant
$clientsecret = "9gAZgM3A5Bo137i~_o06zU~r0nXw.._BuR"                                      #Its Client secret
$redirectUri = "https://jwt.ms/”                                                          #App Registration’s Redirect URI

$postParams = @{resource = "$resource"; client_id = "$clientId"; client_secret = "$clientsecret"; grant_type = "client_credentials"}
$response = Invoke-RestMethod -Method POST -Uri "$authurl/oauth2/token" -Body $postParams


                                                                                          #Without User.Read.All permissions, you cannot view the details of the members.




################################# User UPN Input #######################################
<#$choice = Read-Host "Choose the option by entering the number corresponding to the option when asked for.... `n
                    1) MFA One Time Bypass Based on Detection of Sign in Event 
                    2) MFA Bypass for a specified amount of seconds 
                    3) MFA Bypass for Default 10 minutes
                    
                    Please enter your choice (1, 2 or 3)  "            ###################################### Intiial option to choose Time based or sign in based ###################                            




#$choice2 = Read-Host " `n `n `n `n `n Choose whether you would like to have this exclusion irrespective of application, or if you need it to be Application Specific.`n
                            A) Irrespective of application

                            B) Application Specific (If you choose this option, you will need the App ID of the application) 
                            
                            Please enter your choice (A or B)  "          ###################################### Second option to choose if they want it App based ###################

<#if ($choice2 -eq "B") { Write-Output "`n `n `n Sorry, this option is not available right now. This is still a Work-In-Progress "
                        Break
                         }         ###################################### TO STOP/BREAK till we finish this option ##########################
#>                             ###################################### TO STOP/BREAK till we finish this option ##########################

#$User = Read-Host ("Please enter the UPN of the user `n ")                                ##Input UPN 



if ($AppID.Length -eq 0){$choice2 = "A"}
else{$choice2 = "B"}

if($timer -eq 0){$choice = "1"} 
else{$choice = "2"}



############################################################################################################################################################
################################################## Checking for validity of application  ###################################################################
############################################################################################################################################################



$ErrorActionPreference = "SilentlyContinue"

if ($choice2 -eq "B")
    {
        $AppIdVerificationURL = 'https://graph.microsoft.com/beta/applications/?$search="' + "appId:$AppID`"" 
        $AppIdVerificationRaw = Invoke-RestMethod -Headers @{Authorization = "Bearer $($response.access_token)"; consistencylevel = "eventual"} -Uri $AppIdVerificationURL -Method GET -ErrorVariable ErrorCatch2

        if ($ErrorCatch2)                       ###################################### ERROR HANDLING FOR INVALID APP ######################################
        {                                                                                                                                                     #### ERROR HANDLING FOR INVALID UPN ###
            Write-Output " `n `n There was a problemn with getting the Application details, please recheck the AppID"                                           #### ERROR HANDLING FOR INVALID UPN ###
            Write-Output "  `nThe error is as below : `n `n $errorCatch2 "
            Break
        }

    }

$ErrorActionPreference = "Continue"

############################################################################################################################################################
################################################## Get User's Object ID to search in CA  ###################################################################
############################################################################################################################################################

$ErrorActionPreference = "SilentlyContinue"

$UserInfoURL = 'https://graph.microsoft.com/beta/users/' + $User                                                                                         ##Build URL for the graph query for user
$UserInfoRaw = Invoke-RestMethod -Headers @{Authorization = "Bearer $($response.access_token)"} -Uri $UserInfoURL -Method GET -ErrorVariable ErrorCatch  ## Get the raw response needed


if ($ErrorCatch)                       ###################################### ERROR HANDLING FOR INVALID UPN ######################################
    {                                                                                                                                                     #### ERROR HANDLING FOR INVALID UPN ###
        Write-Output " `n `n There was a problemn with getting the User details, please recheck the UPN, and make sure the user is not a guest account "          #### ERROR HANDLING FOR INVALID UPN ###
        Write-Output "  `nThe error is as below : `n `n $errorCatch "
        Break
    }


$userObjectId = $userInforaw.id ## Store User Object ID

$ErrorActionPreference = "Continue"






############################################################################################################################################################
################################################## Get Group IDs the user is a member of ###################################################################
############################################################################################################################################################

$ErrorActionPreference = "SilentlyContinue"

$UserGroupsURL = 'https://graph.microsoft.com/beta/users/' + $User + '/memberOf'                                                                                   ## Build URL for the graph query
$groupsRaw1 = Invoke-RestMethod -Headers @{Authorization = "Bearer $($response.access_token)"} -Uri $UserGroupsURL -Method GET -ErrorVariable ErrorCatch3          ## Get the raw response needed



<#if ($ErrorCatch3)                       ###################################### ERROR HANDLING FOR INVALID UPN ######################################
    {                                                                                                                                                     #### ERROR HANDLING FOR INVALID UPN ###
        Write-Output "The user is not part of any groups "          #### ERROR HANDLING FOR INVALID UPN ###
    }
$ErrorActionPreference = "Continue"
#>



$GroupsRaw2 = $groupsRaw1.Value                                                                                                          ## Capture value of the raw data
$Groups = $GroupsRaw2 | select id, DisplayName                                                                                           ## Filter out by DisplayName, GroupID










############################################################################################################################################################
############################### Get Roles of the user and convert it to RoleTemplateID values from their Directory##########################################
############################################################################################################################################################

$AllDirectoryRolesURL = 'https://graph.microsoft.com/beta/directoryroles/'                                                                              # Build URL for the graph query
$AllDirectoryRoles = (Invoke-RestMethod -Headers @{Authorization = "Bearer $($response.access_token)"} -Uri $AllDirectoryRolesURL -Method GET).value    # Get the raw response needed for all directory roles


    foreach ($r in $Groups) {                                                                                                                            ## The earlier Group output we pulled, has Role IDs in it as well. 
                                                                                                                                                        ## So we go through them and check if they are Roles 
            $Role = $AllDirectoryRoles | where id -eq $r.id
            $TemplateId = $Role | select roleTemplateId, displayName
          ##  Write-Output " $FinalTemplateIDs"                                                                                                           #### For Debugging purposes 
            $UserRoleTemplateIDs += $TemplateId                                                                                                         #### Making an array to make sure we can reference it later to compare
                                                                                                                                                        #### into Roles of CA policy ####
        }         ###################################### Conversion of Role To Role Template ID ######################################


############################################################################################################################################################
##########################################################Role Output for debug inforamtion################################################################
############################################################################################################################################################
if ($UserRoleTemplateIDs.Count -eq 0) {Write-Output " `n `n `n The User is not part of any directory roles..."} else {
Write-Output "Object ID                                     | Role Name"                                                                                  ######################### Output Roles for debug inforamtion #################
Write-Output "___________________________________________________________"                                                                                ######################### Output Roles for debug inforamtion #################

$UserRoleTemplateIDs | ForEach-Object {
    Write-Output "$($_.roletemplateID)          |  $($_.DisplayName)"
    }  ###################################### Output Roles for Debug Information ######################################             

}



############################################################################################################################################################
##########################################################Group Output for debug inforamtion################################################################
############################################################################################################################################################

if ($groups.Count -eq 0) {Write-Output " `n `n `n The User is not part of any groups..."} else {
Write-Output " `n `n The user $user is part of the following group(s) `n"                  ######################### Output Group for debug inforamtion #################
Write-Output "Object ID                                     | DisplayName"          ######################### Output Group for debug inforamtion #################
Write-Output "___________________________________________________________"          ######################### Output Group for debug inforamtion #################
Foreach ($a in $Groups)                                                           ######################### Output Group for debug inforamtion #################      #This can be removed in the final script
    {                                                                             ######################### Output Group for debug inforamtion #################
        $b = $a.DisplayName                                                       ######################### Output Group for debug inforamtion #################
        $c = $a.id                                                                ######################### Output Group for debug inforamtion #################
        Write-Output "$c          | $b"                                             ######################### Output Group for debug inforamtion #################
    }


}






############################################################################################################################################################
##################################### Get Enabled CA Policies from the tenant where MFA is a control########################################################
############################################################################################################################################################


Write-Output " `n `n Sending Graph query to get CA policies and its properties . . . . . . `n " 


$CAPoliciesURL = "https://graph.microsoft.com/beta/identity/conditionalAccess/policies"
$CAPRaw1 = (Invoke-RestMethod -Headers @{Authorization = "Bearer $($response.access_token)"} -Uri $CAPoliciesURL -Method GET).value                                  ## Get the raw response needed
$CAPs = $CAPRaw1 | select id, DisplayName, state, grantControls, Conditions                                                                                          ## Filter our for needed attributes
$EnabledCapsForMFA = $Caps | where {($_.GrantControls.BuiltInControls -contains "mfa") -and ($_.state -eq "enabled")}                                                ##Filter based on MFA and state of policy


Write-Output " `n `n "






## Write-Output " Starting to check the resultant set of CA policies . . . . . . `n "                                                                                  ## Debug Info

############################################################################################################################################################
############################################################################################################################################################
##################################### Figure out if CA is in the resultant set of policies or not ##########################################################
############################################################################################################################################################
############################################################################################################################################################


## At this point, the Groups/Roles IDs that the user is part of, is stored in $Groups , or otherwise, $Groups.ID

## CA policies that we need to check in, are stored in $EnabledCapsForMFA

Foreach ($x in $EnabledCapsForMFA)                                                 ################## Per Policy that is available in the $EnabledCapsForMFA, we check if we need to consider ##########################

{

   # Write-Output "`n Checking CA Policy `"$($x.displayName)`""                                  ############# Debug Info ######################
    $InFinal = $False                                                                          ############# We are using this temp parameter to decide in the end if a CA policy has to be in the resultant #########################
                                                                                               ############# If we find an exclusion in any way for any each CA policy, we flip this value to exclude checking #######################
    
    
    $endcheck = $False                                                                         ############# This parameter to cut short the loop and come out to check other policies, by default we set this to False ##############

        $Conditions = $x.Conditions.Users                                                      ############# Filtering to get Users, Groups and Roles defined in theCA policy #################


##################### 1)  Checking User Exclusion Condition. If User is already Excluded, we should not touch the CA policy for which we set the EndCheck to True ##################################

## // CheckExclusionUser 

        if ($userInforaw.id -in $Conditions.ExcludeUsers)                                                  ######## Checking User Exclusion ###############
            {                                                                                              ######## Checking User Exclusion ###############
            $InFinal = $False                                                                              #### Setting $InFinal parameter to False ####### (We use this parameter to identify in the end if a 
                                                                                                           #### CA policy needs to be considered or not)
            $endcheck = $True                                                                              ### Flipping $endcheck to True to avoid other IF conditions from applying on this anymore ####
            $dp = $x.DisplayName
            $userdp = $userInforaw.displayName
            $useroid = $_.id

         #   Write-Output "User Exclusion - Conditional Access policy `"$dp`" contains the User `"$userdp`" `( object ID - $userObjectID `) in Exclude Condition which the User is part of"              ######## Debug Info                                                    
            }



################ 2) A  Checking Group Exclusion Condition. If User is already Excluded through group, we should not touch the CA policy ##########################


## // CheckExclusionGroup 

 $Groups | ForEach-Object {
          if ($_.id -in $Conditions.excludeGroups)
                {

       #             Write-Output "Group Exclusion- Conditional Access policy `"$($x.displayName)`" contains the group `"$($_.DisplayName)`" `( object ID - $($_.id) `) in Exclude Condition which the User is part of "        ### Debug Info
                    $InFinal = $False                                                                     #### Setting $InFinal parameter to False ####### (We use this parameter to identify in the end if a CA 
                                                                                                          #### policy needs to be considered or not)
                    $endcheck = $True                                                                     #### Flipping $endcheck to True to avoid other IF conditions from applying on this CAP anymore ####
                }
        }

################ 2) B  Checking Role Exclusion Condition. If User is already Excluded through Role, we should not touch the CA policy ##########################

## // CheckRoleExclusions

         $UserRoleTemplateIDs | ForEach-Object {
          if ($_.roletemplateID -in $Conditions.excludeRoles)
                {
      #              Write-Output "Role Exclusion- Conditional Access policy `"$($x.DisplayName)`" contains the role `"$($_.DisplayName)`" `( Role Template ID - $($_.RoleTemplateid) `) in Exclude Condition which the User is assigned to"
                    $InFinal = $False                                                                      #### Setting $InFinal parameter to False ####### (We use this parameter to 
                                                                                                           #### identify in the end if a CA policy needs to be considered or not)
                    $endcheck = $True                                                                      ###  Flipping $endcheck to True to avoid other IF conditions from applying on this anymore ####
                }
        }



################ 3)  Checking In Remaining CA policies if User in Directly Included . If User is already Excluded through group or user condition , we should not touch the CA policy (EndCheck tells us that)################


##Direct User Inclusion Check

        if (($userObjectId -in $Conditions.IncludeUsers) -and ($endcheck -eq $False))     ######## Checking User Inclusion and checking if this needs to be skipped based on earlier Exclude condition ###############
            {                                                                             ######## Checking User Inclusion ###############
            $InFinal = $True                                                              #### Setting temporary parameter to True ####### (We use this parameter to identify in the end if a CA policy needs to be considered or not)
  ##          Write-Output "Inclusion script running"                                       ### Debug Information ###
 ##           Write-Output " $InFinal "                                                     ### Debug Information ###
            }



## User's Group Inclusion Check

if ($endcheck -ne $True)                                                                      ########### Check if Already Excluded by something using EndCheck Variable #######################

        {
         $Groups | ForEach-Object {
                  if ($_.id -in $Conditions.includeGroups)
                        {
                            $dp = $x.displayName
                            $gpName = $_.DisplayName
                            $gpID = $_.id
                          ##  Write-Output "Group Exclusion- Conditional Access policy `"$dp`" contains the group `"$gpName`" `( object ID - $gpid `) in Exclude Condition which the User is part of `n"
                            $InFinal = $True                                                      #### Setting $InFinal parameter to False ####### (We use this parameter to identify in the end if a CA policy needs to be considered or not)
                            $endcheck = $False                                                    ### Flipping $endcheck to True to avoid other IF conditions from applying on this anymore ####
                            $dp = $Null
                            $gpName = $Null
                        }
                }

        }

##Direct Role Inclusion Check
if ($endcheck -ne $True){                                                                          ########### Check if Already Excluded by something using EndCheck Variable #######################
        $UserRoleTemplateIDs | ForEach-Object {
          if ($_.roletemplateID -in $Conditions.includeRoles)
                {
                    $InFinal = $True                                                               #### Setting $InFinal parameter to True ####### (We use this parameter to identify in the end if a CA policy needs to be considered or not)
                    $endcheck = $False                                                             ### Flipping $endcheck to False ####
                }
        }
}



##Write-Output " $dp "
##Write-Output " $InFinal"

################ Check and Mark CA Policy for Resultant if $InFinal is set to True #######################

#CalculateResultForTrue ##Function Defined in the beginning





        if (($InFinal -eq $True) -and ($endcheck -ne $True))                                          ######### Checking if $InFinal has been triggered to True, and if True, add to resultant set of policies #################
            {
            
        $result = New-Object -TypeName PSObject
       # $result1 = New-Object -TypeName PSObject
        $result | Add-Member -MemberType NoteProperty -Name PolicyID -Value $x.id
      #  $result1 | Add-Member -MemberType NoteProperty -Name PolicyID -Value $x.id
        $result | Add-Member -MemberType NoteProperty -Name DisplayName -Value $x.DisplayName
       # $result1 | Add-Member -MemberType NoteProperty -Name DisplayName -Value $x.DisplayName
       # $output1 += $result1
        $result | Add-Member -MemberType NoteProperty -Name NeedsToBeInResultant -Value "True"
        $result | Add-Member -MemberType NoteProperty -Name conditions -Value $x.conditions

        $pURL = $Null
        $pURL = "https://graph.microsoft.com/beta/identity/conditionalAccess/policies/" + $x.id
        
        $result | Add-Member -MemberType NoteProperty -Name PolicyURL -Value $pURL                    ##### Adding URL into the result to make it easier in the later logic part, Remove if not required ##########

        $endresult += $result                                                                         ###### Storing resultant set of CA policies that we need to take action on, in the array/table $endresult #################

            }


}




if($endresult.Count -eq "0")                    ###################################### If NO Policies, then speak about it and Break ######################################
    { 
    
    Write-Output " `n There are no CA policies the user needs to be excluded from to bypass MFA from "               ########## Handling when there are no policies to exclude the user from  #############
    Break
    } 
else {
Write-Output " `n The policies that are enabled and have MFA as atleast one condition : `n"

#$output1
$endresult

                                                                                               ################# Resultant Set of CA Policies that we need to act on ###################

}                                      ###################################### Else, Output the policies to show and store   ######################################



#####################################################################################################################
#####################################################################################################################
######################### Copy end result CA policies into a read-Only Variable #####################################
### This is Critical since we need to reverse actions later on these policies and we need to reference them again ###
#####################################################################################################################
#####################################################################################################################

#############  Set-Variable -Name Reference -Value $endresult -option ReadOnly                                           ######## DIDNT WORK AS EXPECTED

#####################################################################################################################
#####################################################################################################################


#####################################################################################################################################################
#####################################################################################################################################################
######################### Copy end result CA policies into a Variable separately ####################################################################
### This is Critical since we need to reverse actions later on these policies and we need to reference them again ###################################
#####################################################################################################################################################
## Doing a simple $variable1 = $Variable2 does not work here, since edits on $variable2 somehow affects $variable1 ##################################
#####################################################################################################################################################
#####################################################################################################################################################

Function Restore-capmemory {                                                                                        #### TO be used when you need original data of resultant ################
                                                                                                                    #### policies into a variable of choice. To do this,     ################ 
                                                                                                                    #### please use $variable = Restore-Capmemory. Eg: Line 374  ############
    # Serialize and Deserialize data using BinaryFormatter                                                          
$ms = New-Object System.IO.MemoryStream
$bf = New-Object System.Runtime.Serialization.Formatters.Binary.BinaryFormatter
$bf.Serialize($ms, $endresult)
$ms.Position = 0

#Deep copied data
##Set-Variable -Name capread -Value $bf.Deserialize($ms) -Option ReadOnly                                             ### Setting the new Variable capmemory to write  ###
$capmemory = $bf.Deserialize($ms)
$ms.Close()
$capmemory
}         #### TO be used when you need original data of resultant policies into a variable of choice. To do this, please use $variable = Restore-Capmemory. Eg: Line 374 ####

### Memory copy reference : #### https://stackoverflow.com/questions/29699026/powershell-copy-an-array-completely ####################################
$capmemory = Restore-capmemory

#####################################################################################################################################################
#####################################################################################################################################################

#####################################################################################################################################################
######################################################################################################################################################
################################################## Function to Start Exclusions ######################################################################
######################################################################################################################################################
######################################################################################################################################################


Function CapStart {

Foreach ($i in $capmemory)
    {

    if ($i.conditions.users.excludeUsers -notcontains $userObjectid)
            {
                    $i.conditions.users.excludeUsers += $userObjectId
             }
    if (($i.conditions.users.excludeUsers).count -eq 1)                                                                                         ### Dirty Hack to help ConvertTo-Json to keep [] for this property ###
            {
                    $i.conditions.users.excludeUsers += $userObjectId                                                                     ### Else, if number of properties is just 1, PS doesnt add [], Graph call fails ###
            }

    $i.conditions.users = $i.conditions.users | select ExcludeUsers
    $i.conditions = $i.conditions | select Users
    $j = ConvertTo-Json($i | select Conditions) -Depth 20

     
    $req= Invoke-WebRequest -Headers @{Authorization = "Bearer $($response.access_token)"} -Uri $i.PolicyURL -ContentType "Application/json" -body $j -Method PATCH  
    $req2= Invoke-RestMethod -Headers @{Authorization = "Bearer $($response.access_token)"} -Uri $i.PolicyURL -ContentType "Application/json" -Method GET    

    $capmemory = Restore-capmemory
 
    if ($req2.conditions.users.excludeUsers -contains "$userObjectId") 
            
         { Write-Output " `n Success making an exclusion with the policy $($req2.DisplayName) `n " }        ######## Checking if user is in exclusion ##############
         else { Write-Output " `n Something went wrong in modifying the policy for Exclusion process to using Graph for policy $($i.DisplayName) `n "}    
    }

}          ######### Function Created to start Exclusion of Users in the Policies ###########

##$PolicyExcludedTime = (Get-Date).ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss")

##$PolicyExcludedTimeUTC = [datetime]::parseexact($PolicyExcludedTime, 'yyyy-MM-dd HH:mm:ss', $null)  



########################################################################################################################################################################################################
########################################################################################################################################################################################################
########################################################################################################################################################################################################

########################################################################################################################################################################################################
################################################## Function to reverse the Exclusions ##################################################################################################################
######################################################################################################################################################################################################## 


Function capReverse {

Foreach ($i in $capmemory)
    {

    
    $Req= Invoke-RestMethod -Headers @{Authorization = "Bearer $($response.access_token)"} -Uri $i.PolicyURL -ContentType "Application/json" -Method GET  ####### Check for Latest Policy Condition for Same URl to re-evaluate Exclusion #######
    $LP = [system.Array]$Req

    while($LP.conditions.users.excludeUsers -contains $userObjectid)
            {
                    $j = @()
                    $j = $LP.conditions.users.excludeUsers | Where-Object {$_ -ne $userObjectid}

                    $LP.conditions.users.excludeUsers = [System.Array]$j
             }

    if( ($LP.conditions.users.excludeUsers).Count -eq 1)                                               ######## Dirty hack to avoid problems with single property | Conversion to Json problem with PS ###########
        {
         $LP.conditions.users.excludeUsers += $LP.conditions.users.excludeUsers
        }

    

    $LP.conditions.users = $LP.conditions.users | select ExcludeUsers
   # $LP.conditions = $LP.conditions | select Users                                                    ########################## FUTURE PLAN TO TARGET ONLY EXCLUDE USERS PROPERTY #################################
    $j = ConvertTo-Json($LP | select Conditions) -Depth 20

     
    $req= Invoke-WebRequest -Headers @{Authorization = "Bearer $($response.access_token)"} -Uri $i.PolicyURL -ContentType "Application/json" -body $j -Method PATCH 
    
      
    $req2= Invoke-RestMethod -Headers @{Authorization = "Bearer $($response.access_token)"} -Uri $i.PolicyURL -ContentType "Application/json" -Method GET    

    $capmemory = Restore-capmemory

    if ($req2.conditions.users.excludeUsers -notcontains "$userObjectId") 
        { Write-Output " `n Success reversing exclusion from policy $($req2.DisplayName) `n " }     ########### Checking if user is in exclusion ##############
    else 
        { Write-Output " `n Something went wrong in modifying the policy for CAP MFA ByPass reversal using Graph for policy $($i.DisplayName) `n "}
          
    } 


}      ######### Function Created to reverse Exclusion of Users in Policies modified ###############


##########################################################################################################################################################################################################################################################
##########################################################################################################################################################################################################################################################
##########################################################################################################################################################################################################################################################

## 1) Time Based Condition -Default OR defined
## 2) Application Based Condition [Basic] //WARNING : NEED TO TAKE CARE OF RESOURCES/ SCOPES
## 3) Based on the NEXT successful Sign-in Log 

##########################################################################################################################################################################################################################################################
##########################################################################################################################################################################################################################################################
##########################################################################################################################################################################################################################################################






########################################################################################################################################################
##################              ACTUAL    START      OF      SCRIPT     FOR    ONE-TIME    SIGN   IN   [ BYPASS ]           ############################
########################################################################################################################################################

Switch ( $Choice2 )           #################################### Based on All Apps Condition, choose A or B ###########################
{
    A
        {
            Switch ( $choice )    ########################### Honor the method of exclusion chosen ( One time sign in/Time Based ) ##########                                                                                                                                                                                                                                                                                                                                                                                                                              {
            {
            1{

            Write-Output " `n We will now attempt to modify the policies to Exclude the User from the CA policies mentioned `n "
            #pause
            CapStart                                                                                                                                                        ###################### CAP Start Function to Put User to Exclusion ###############

                    $PolicyExcludedTimeRaw = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")

                    $conversion = [datetime]::parseexact($PolicyExcludedTimeRaw, 'yyyy-MM-dd HH:mm:ss', $null) 

                    Set-Variable -Name PolicyExcludedTime -Value $conversion -Scope Global
            
            Write-Output " `n We will begin to check Sign in events to detect the next sign in for the user, post which we would go ahead to reverse the modifications done"
            #pause





            $SignInLogsURL = "https://graph.microsoft.com/beta/auditlogs/signins?$filter=startswith(UserPrincipalName," + "'" + $User + "'" + ")&" + "`$top=1" #| Write-Output

            $Finished = 0

            While ($Finished -eq 0)                                                                                                                                        ###################### Waiting for success Sign in ###################
                {
                    $SignInEvent = (Invoke-RestMethod -Headers @{Authorization = "Bearer $($response.access_token)"} -Uri $SigninLogsURL -Method GET).Value                    
                                                                                                                                    
                    $t = [datetime]($SignInEvent.CreatedDateTime)

                    if ($t -gt $PolicyExcludedTime)                                                                                                                 ############## CHECK EVENT TIME ################
                        {
                            if ($SignInEvent.status.errorCode -eq 0)                                                                                                ########## STATUS CODE FOR SUCCESS #############
                                    {

                                       Write-Output " `n We detected a successful Sign-in for the user! "
                                       $finished = 1
                                    }
                        }
                    else
                        {
                
                            Write-Output " `n Waiting for Sign in events to generate the latest success event . . . . "
                            Start-Sleep -Seconds 30
                        }


                 }

            capReverse                                                                                                                     ########################## REVERSE CHANGES DONE #############################

        }
              
            2{
          <# $timer = Read-Host "Enter the number of seconds post which you want the exclusion to be removed (Example, for 300 seconds, type in 300) Suggested values are >60s
           
           Enter here  " #>


           Write-Output " `n We will now attempt to modify the policies to Exclude the User from the CA policies mentioned `n "
                #pause
               CapStart                                                                                                                                                        ###################### CAP Start Function to Put User to Exclusion ###############

                        $PolicyExcludedTimeRaw = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")

                        $conversion = [datetime]::parseexact($PolicyExcludedTimeRaw, 'yyyy-MM-dd HH:mm:ss', $null) 

                        Set-Variable -Name PolicyExcludedTime -Value $conversion -Scope Global
            
                
                Write-Output " `n We will now begin the timer ( $timer seconds ) post which the user will be removed from Exclusion `n"
                


             <#   $SignInLogsURL = "https://graph.microsoft.com/beta/auditlogs/signins?$filter=startswith(UserPrincipalName," + "'" + $User + "'" + ")&" + "`$top=1" #| Write-Output

                

               
               $SignInEvent = (ConvertFrom-JSON((Invoke-WebRequest -Headers @{Authorization = "Bearer $($response.access_token)"} -Uri $SigninLogsURL -Method GET).Content)).Value
               $t = [datetime]($SignInEvent.CreatedDateTime) #>

               $time = [int32]$timer

               While ( $time -gt 0 )
               {
                    Sleep 1
                    $time--
                    Write-Output(" $time seconds remaining ")
               }


              ## Start-Sleep -Seconds $timer

               Write-Output " `n $timer of seconds has passed. We will reverse the Exclusion now "
               
               capReverse   
       
       
       
        
        }

            }
         }
     
    B

      {

       #$appId = Read-Host " `n `n `n Please enter the AppID of the application "
       $endresult = $endresult| where {($_.conditions.Applications.excludeApplications -Notcontains "$AppId") -and ($_.conditions.Applications.includeApplications -contains "$AppId") }
       #pause
       
       Write-Output "`n `n `n The resultant set of policies to take action based on AppID `n"
       $endresult

          
           Switch ( $choice )    ########################### Honor the method of exclusion chosen ( One time sign in/Time Based ) ##########                                                                                                                                                                                                                                                                                                                                                                                                                              {
            {
            1{

            Write-Output " `n We will now attempt to modify the policies to Exclude the User from the CA policies mentioned `n "
            #pause
            Restore-capmemory

            CapStart                                                                                                                                                        ###################### CAP Start Function to Put User to Exclusion ###############

                    $PolicyExcludedTimeRaw = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")

                    $conversion = [datetime]::parseexact($PolicyExcludedTimeRaw, 'yyyy-MM-dd HH:mm:ss', $null) 

                    Set-Variable -Name PolicyExcludedTime -Value $conversion -Scope Global
            
            Write-Output " `n We will begin to check Sign in events to detect the next sign in for the user, post which we would go ahead to reverse the modifications done"
            #pause





            $SignInLogsURL = "https://graph.microsoft.com/beta/auditlogs/signins?$filter=startswith(UserPrincipalName," + "'" + $User + "'" + ")&" + "`$top=1" #| Write-Output

            $Finished = 0

            While ($Finished -eq 0)                                                                                                                                        ###################### Waiting for success Sign in ###################
                {
                    $SignInEvent = (Invoke-RestMethod -Headers @{Authorization = "Bearer $($response.access_token)"} -Uri $SigninLogsURL -Method GET).Value                    
                                                                                                                                    
                    $t = [datetime]($SignInEvent.CreatedDateTime)

                    if ($t -gt $PolicyExcludedTime)                                                                                                                 ############## CHECK EVENT TIME ################
                        {
                            if ($SignInEvent.status.errorCode -eq 0)                                                                                                ########## STATUS CODE FOR SUCCESS #############
                                    {

                                       Write-Output " `n We detected a successful Sign-in for the user! "
                                       $finished = 1
                                    }
                        }
                    else
                        {
                
                            Write-Output " `n Waiting for Sign in events to generate the latest success event . . . . "
                            Start-Sleep -Seconds 30
                        }


                 }

            capReverse                                                                                                                     ########################## REVERSE CHANGES DONE #############################

        }
              
            2{
          <# $timer = Read-Host "Enter the number of seconds post which you want the exclusion to be removed (Example, for 300 seconds, type in 300) Suggested values are >60s
           
           Enter here  " #>


           Write-Output " `n We will now attempt to modify the policies to Exclude the User from the CA policies mentioned `n "
                #pause
                $capmemory = Restore-capmemory

                CapStart                                                                                                                                                        ###################### CAP Start Function to Put User to Exclusion ###############

                        $PolicyExcludedTimeRaw = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")

                        $conversion = [datetime]::parseexact($PolicyExcludedTimeRaw, 'yyyy-MM-dd HH:mm:ss', $null) 

                        Set-Variable -Name PolicyExcludedTime -Value $conversion -Scope Global
            
                
                Write-Output " `n We will now begin the timer ( $timer seconds ) post which the user will be removed from Exclusion `n"
                


              <#  $SignInLogsURL = "https://graph.microsoft.com/beta/auditlogs/signins?$filter=startswith(UserPrincipalName," + "'" + $User + "'" + ")&" + "`$top=1" #| Write-Output

                

               
               $SignInEvent = (ConvertFrom-JSON((Invoke-WebRequest -Headers @{Authorization = "Bearer $($response.access_token)"} -Uri $SigninLogsURL -Method GET).Content)).Value
               $t = [datetime]($SignInEvent.CreatedDateTime)  #>

               $time = [int32]$timer

               While ( $time -gt 0 )
               {
                    Sleep 1
                    $time--
                    Write-Output(" $time seconds remaining ")
               }


              ## Start-Sleep -Seconds $timer

               Write-Output " `n $timer of seconds has passed. We will reverse the Exclusion now "
               
               capReverse   
       
       
       
        
        }
        
            
            }
          
            

      }                  #################################### Based on Application Specific Condition, Work in Progress ################################

}


    ####### NOTE: Removing switch of a User condition doesnt remove conditions ##########



    ## Example App ID : 20ef2bd3-0e69-45f1-8545-bc8c0c14b112 ##
