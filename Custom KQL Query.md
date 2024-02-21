# Microsoft Endpoint Defender
## Post mounted activities of ISO files
### Query Description 
#### Detect the mounted drive letter, drive path, and files which got executed under the mounted path and the corresponding command line which executed the file.
```
DeviceEvents
| where ActionType == "UsbDriveMounted"
| extend DriveLetter = tostring(todynamic(AdditionalFields).DriveLetter)
| extend ProductName = tostring(todynamic(AdditionalFields).ProductName)
| extend BusType = tostring(todynamic(AdditionalFields).BusType)
| where BusType == "15"
| project Timestamp,DeviceName,DriveLetter,ProductName
| where isnotempty(DriveLetter)
| join ( DeviceEvents
| where ActionType == "ShellLinkCreateFileEvent"
| extend ShellLinkWorkingDirectory = tostring(todynamic(AdditionalFields).ShellLinkWorkingDirectory)
| parse ShellLinkWorkingDirectory with DriveLetter '\\' *
) on DeviceName,DriveLetter
| project Timestamp=ProcessCreationTime,ReportId,DeviceName=DeviceName1,DeviceId,MountedVendorName=ProductName,MountedLetter=DriveLetter,MappingFilename=FileName,ShellLinkWorkingDirectory
| join kind = leftouter ( 
DeviceProcessEvents
| parse kind=regex ProcessCommandLine with "\\s\"" MountedLetter ":" MappingFilename "\""
| extend MappingFilename = split(MappingFilename,"\\")[-1]
| extend MountedLetter=strcat(MountedLetter,":"),MappingFilename=strcat(MappingFilename,".lnk")
) on MountedLetter,DeviceName,MappingFilename
| where isnotempty(ProcessCommandLine)
```

## Unique Emails which are having same malicious URL
### Query Description 
#### Detect number of unique URLs which sent from different SenderEmailAddress with different subjects to different ReceipientEmailAddress along with SenderIPv4 and its geo location
```
EmailUrlInfo
| where Url has "<URL_Domain_Name>"
| distinct Url,NetworkMessageId
| join EmailEvents on NetworkMessageId
| where SenderFromAddress !has "ingrammicro"
| extend GEOIP = geo_info_from_ip_address(SenderIPv4)
| extend Country = tostring(todynamic(GEOIP).country),State = tostring(todynamic(GEOIP).state)
| project Timestamp,SenderFromAddress, RecipientEmailAddress, Subject, Url, SenderIPv4, Country, State
```
