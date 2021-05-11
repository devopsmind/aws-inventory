#!/usr/bin/env python3

import boto3,os
import pandas as pd

from datetime import datetime
from datetime import timedelta
from time import gmtime, strftime



#Find current owner ID
boto3.setup_default_session(profile_name="Default")
sts = boto3.client('sts')
ec2 = boto3.resource('ec2')
identity = sts.get_caller_identity()
ownerId = identity['Account']
# import ipdb; ipdb.set_trace()

LIST_SNAPSHOTS_WITHIN_THE_LAST_N_DAYS=os.getenv("LIST_SNAPSHOTS_WITHIN_THE_LAST_N_DAYS","90")




def get_instances():

    #variavel filters
    filters = []
    f1 = {}
    f1['Name'] = 'instance-state-name'
    f1['Values'] = ['running']
    filters.append(f1)
    #filters= [{Name:instance-state-name','Values':['running'] }]
    
    #buscando todas as instancias que estao ativas com a variavel filters
    dic =  ec2con.describe_instances(Filters=filters)
    
    
    #criando colunas a partir da  SecurityGroups
    
    for r_int, v in  enumerate(dic['Reservations']):
          for index,i in enumerate(v['Instances']):
               for sec in i['SecurityGroups']:
                   dic['Reservations'][r_int]['Instances'][index]['SeCG_' + sec['GroupName']] = 1
    
    #criando colunas a partir da Tags
    for r_int, v in  enumerate(dic['Reservations']):
         for index,i in enumerate(v['Instances']):
             try:
               for t in i['Tags']:
                  dic['Reservations'][r_int]['Instances'][index]['Tag_' + t['Key']] = t['Value']
             except Exception as e:
                  print('instancia(s)' + i['InstanceId'] + " não possui Tag  Name" )
                  pass  
    
    inst=[]
    for v in dic['Reservations']:
         for i in v['Instances']:
                 inst.append(i)
    d_instances =inst
   
    return d_instances

def get_volumes():

    d_vols={'VolumeId':[],'InstanceId':[],'AttachTime':[],'State':[],'Iops':[]}
    

   #boto3 library ec2 API describe volumes page
   #http://boto3.readthedocs.org/en/latest/reference/services/ec2.html#EC2.Client.describe_volumes
    # ec2volumes = ec2con.describe_volumes().get('Volumes',[])
    # volumes = sum(
    #     [
    #         [i for i in r['Attachments']]
    #         for r in ec2volumes
    #     ], [])
    # volumeslist = len(volumes)
    
    volumes = ec2.volumes.all()
    try:
       for volume in volumes:
           VolumeId=volume.attachments[0]['VolumeId']
           InstanceId=volume.attachments[0]['InstanceId']
           State=volume.attachments[0]['State']
           AttachTime=volume.attachments[0]['AttachTime']
           Iops = volume.iops
           vols={'VolumeId':VolumeId,'InstanceId':InstanceId,'AttachTime':AttachTime,'State':State,'Iops': Iops}
           for k,v in vols.items():
               d_vols[k].append(v)
    except:
        pass
    return d_vols

def get_snapshots():
    #boto3 library ec2 API describe snapshots page
    #http://boto3.readthedocs.org/en/latest/reference/services/ec2.html#EC2.Client.describe_snapshots
    ec2snapshot = ec2con.describe_snapshots(OwnerIds=[
        ownerId,
    ],).get('Snapshots',[])

    snapshots_counter = 0
    d_snaps={'SnapshotId':[],'VolumeId':[],'StartTime':[],'VolumeSize':[],'Description':[]}
    for snapshot in ec2snapshot:
        snapshot_id = snapshot['SnapshotId']
        snapshot_state = snapshot['State']
        tz_info = snapshot['StartTime'].tzinfo
        # Snapshots that were not taken within the last configured days do not qualify for auditing
        timedelta_days=-int(LIST_SNAPSHOTS_WITHIN_THE_LAST_N_DAYS)
        if snapshot['StartTime'] > datetime.now(tz_info) + timedelta(days=timedelta_days):
            #if snapshots_counter == 0:
            ##    csv_file.write("%s,%s\n"%('EC2 SNAPSHOT',regname))
            #     snaps.append('SnapshotId','VolumeId','StartTime','VolumeSize','Description')
            snapshots_counter += 1
            SnapshotId=snapshot['SnapshotId']
            VolumeId=snapshot['VolumeId']
            StartTime=snapshot['StartTime']
            VolumeSize=snapshot['VolumeSize']
            Description=snapshot['Description']
            
            snaps={'SnapshotId':SnapshotId,'VolumeId':VolumeId,'StartTime':StartTime,'VolumeSize':VolumeSize,'Description':Description}
            for k,v in snaps.items():
                    d_snaps[k].append(v)
    return d_snaps

def get_address():

    #boto3 library ec2 API describe addresses page
    #http://boto3.readthedocs.org/en/latest/reference/services/ec2.html#EC2.Client.describe_addresses
    addresses = ec2con.describe_addresses().get('Addresses',[] )
    addresseslist = len(addresses)
    d_address= {'PublicIp':[],'AllocationId':[],'Domain':[],'InstanceId':[]}
    if addresseslist > 0:
        #csv_file.write("%s,%s\n"%('EIPS INSTANCE',regname))
       # address.append('PublicIp','AllocationId','Domain','InstanceId')
        for address in addresses:
            PublicIp=address['PublicIp']
            try:
                AllocationId=address['AllocationId']
            except:
                AllocationId="empty"
            Domain=address['Domain']
            if 'InstanceId' in address:
                instanceId=address['InstanceId']
            else:
                instanceId='empty'
            address={'PublicIp':PublicIp,'AllocationId':AllocationId,'Domain':Domain,'InstanceId':instanceId}
            for k,v in address.items():
                 d_address[k].append(v)
    return d_address

def get_securitygroups():

    
    #boto3 library ec2 API describe security groups page
    #http://boto3.readthedocs.io/en/latest/reference/services/ec2.html#EC2.Client.describe_security_groups


    def printSecGroup(groupType, permission):
        ipProtocol = permission['IpProtocol']
        try:
            fromPort = permission['FromPort']
        except KeyError:
            fromPort = None
        try:
            toPort = permission['ToPort']
        except KeyError:
            toPort = None
        try:
            ipRanges = permission['IpRanges']
        except KeyError:
            ipRanges = []
        ipRangesStr = ''
        for idx, ipRange in enumerate(ipRanges):
            if idx > 0:
                ipRangesStr += '; '
            ipRangesStr += ipRange['CidrIp']
            securityGroups={'GroupName':groupName,'GroupType':groupType,'IpProtocol':ipProtocol,'FromPort':fromPort,'ToPort':toPort,'IpRangesStr':ipRangesStr}
            for k,v in securityGroups.items():
                    d_securityGroups[k].append(v)



    securityGroups = ec2con.describe_security_groups(
        Filters = [
            {
                'Name': 'owner-id',
                'Values': [
                    ownerId,
                ]
            }
        ]
    ).get('SecurityGroups')
    d_securityGroups={'GroupName':[],'GroupType':[],'IpProtocol':[],'FromPort':[],'ToPort':[],'IpRangesStr':[]}
    if len(securityGroups) > 0:
        for securityGroup in securityGroups:
            groupName = securityGroup['GroupName']
            # securityGroupId = securityGroup['GroupId']
            ipPermissions = securityGroup['IpPermissions']
            for ipPermission in ipPermissions:
                groupType = 'ingress'
                printSecGroup (groupType, ipPermission)
            ipPermissionsEgress = securityGroup['IpPermissionsEgress']
            for ipPermissionEgress in ipPermissionsEgress:
                groupType = 'egress'
                printSecGroup (groupType, ipPermissionEgress)

    return d_securityGroups

def get_rds(region):

#RDS Connection beginning
    rdscon = boto3.client('rds',region_name=region)

    #boto3 library RDS API describe db instances page
    #http://boto3.readthedocs.org/en/latest/reference/services/rds.html#RDS.Client.describe_db_instances
    rdb = rdscon.describe_db_instances().get(
    'DBInstances',[]
    )
    rdblist = len(rdb)
    d_dbs={'DBInstanceIdentifier':[],'DBInstanceStatus':[],'DBName':[],'DBInstanceClass':[]}
    for dbinstance in rdb:
        DBInstanceIdentifier = dbinstance['DBInstanceIdentifier']
        DBInstanceClass = dbinstance['DBInstanceClass']
        DBInstanceStatus = dbinstance['DBInstanceStatus']
        try:
            DBName = dbinstance['DBName']
        except:
            DBName = "empty"
        items_dbs={'DBInstanceIdentifier':DBInstanceIdentifier,'DBInstanceStatus':DBInstanceStatus,'DBName':DBName,'DBInstanceClass':DBInstanceClass}
        for k,v in items_dbs.items():
                d_dbs[k].append(v)
    
    return d_dbs

def get_loadbalancers(region):
#ELB connection beginning
    elbcon = boto3.client('elb',region_name=region)

    #boto3 library ELB API describe db instances page
    #http://boto3.readthedocs.org/en/latest/reference/services/elb.html#ElasticLoadBalancing.Client.describe_load_balancers
    loadbalancer = elbcon.describe_load_balancers().get('LoadBalancerDescriptions',[])
    loadbalancerlist = len(loadbalancer)
    d_loadbalancers={'LoadBalancerName':[],'DNSName':[],'CanonicalHostedZoneName':[],'CanonicalHostedZoneNameID':[]}
    for load in loadbalancer:
        LoadBalancerName=load['LoadBalancerName']
        DNSName=load['DNSName']
        try:
           CanonicalHostedZoneName=load['CanonicalHostedZoneName']
           CanonicalHostedZoneNameID=load['CanonicalHostedZoneNameID']
        except:
            CanonicalHostedZoneName,CanonicalHostedZoneNameID=("","")
            
        loadbalancers={'LoadBalancerName':LoadBalancerName,'DNSName':DNSName,'CanonicalHostedZoneName':CanonicalHostedZoneName,'CanonicalHostedZoneNameID':CanonicalHostedZoneNameID}
        for k,v in loadbalancers.items():
                d_loadbalancers[k].append(v)

    return d_loadbalancers

def get_iams(region):
 #IAM connection beginning
    iam = boto3.client('iam', region_name=region)
    d_users={'User':[],'Policies':[]}
    #boto3 library IAM API

    #http://boto3.readthedocs.io/en/latest/reference/services/iam.html
    #csv_file.write("%s,%s\n"%('IAM',regname))
    users = iam.list_users()['Users']
    for user in users:
        user_name = user['UserName']
        policies = ''
        user_policies = iam.list_user_policies(UserName=user_name)["PolicyNames"]
        for user_policy in user_policies:
            if(len(policies) > 0):
                policies += ";"
            policies += user_policy
        attached_user_policies = iam.list_attached_user_policies(UserName=user_name)["AttachedPolicies"]
        for attached_user_policy in attached_user_policies:
            if(len(policies) > 0):
                policies += ";"
            policies += attached_user_policy['PolicyName']

        if(len(policies) > 0):
            policies += ";"
            policies += attached_user_policy['PolicyName']
        items_users={'User':user_name,'Policies':policies}
        for k,v in items_users.items():
                    d_users[k].append(v)
    return d_users

def fix_timezone(data,field):
        try:
           data = data[field].dt.tz_localize(None)
        except:
            pass
        return data


#boto3 library ec2 API describe region page
#http://boto3.readthedocs.org/en/latest/reference/services/ec2.html#EC2.Client.describe_regions

#regions = ec.describe_regions().get('Regions',[] )
region ='sa-east-1'
#EC2 connection beginning
ec2con = boto3.client('ec2',region_name=region)

instances=get_instances()
vols=get_volumes()
snaps=get_snapshots()
loadbalancers=get_loadbalancers(region)
dbs= get_rds(region)
users =get_iams(region)
securityGroups = get_securitygroups()

# import ipdb; ipdb.set_trace()
df1 = pd.DataFrame(instances)
df1["LaunchTime"]=fix_timezone( df1,"LaunchTime" ) 
df2 = pd.DataFrame(vols)
df2["AttachTime"]=fix_timezone(df2,"AttachTime")
df3 = pd.DataFrame(snaps)
df3["StartTime"]=fix_timezone(df3,"StartTime")
df4 = pd.DataFrame(loadbalancers)
df5 = pd.DataFrame(dbs)
df6 = pd.DataFrame(users)
df7 = pd.DataFrame(securityGroups)
# Create a Pandas Excel writer using XlsxWriter as the engine.
writer = pd.ExcelWriter('report.xlsx', engine='xlsxwriter')

# Write each dataframe to a different worksheet.
df1.to_excel(writer, sheet_name='Instancias', index=False)

df2.to_excel(writer, sheet_name='Volumes', index=False)
df3.to_excel(writer, sheet_name='Snapshots', index=False)
df4.to_excel(writer, sheet_name='LoadBalancers', index=False)
df5.to_excel(writer, sheet_name='Banco de Dados', index=False)
df6.to_excel(writer, sheet_name='Usuários', index=False)
df7.to_excel(writer, sheet_name='SecurityGroups', index=False)

### Assign WorkBook
workbook=writer.book
# Add a header format
header_fmt = workbook.add_format({'bold': True,'text_wrap': True,'size':10,
                                                      'valign': 'top','fg_color': '#C1c1c1','border': 1})

                                                    
#format all sheets with replace format in header line
for sheet in writer.sheets:  
    for n in range(1-7):
        for column in df + n:
            #get size content to set column size 
            column_length = max(df7[column].astype(str).map(len).max(), len(column)) 
            #number column
            col_idx = df7.columns.get_loc(column)
            #header line
            writer.sheets[sheet].write(0,col_idx,str(df7.columns[col_idx]),header_fmt)
            #set size column
            writer.sheets[sheet].set_column(col_idx, col_idx, column_length)

### Close the Pandas Excel writer and output the Excel file.
writer.save()
