from redtree_app.models import Appliances


#########################
#       Appliances  	#
#########################
def external_appliances():
    appliances_obj = Appliances.objects.filter(network_type='External')
    if appliances_obj:
        for appliance in appliances_obj:
            if appliance.appliance_ip:
                return appliance.appliance_ip

def internal_appliances():
    appliances_obj = Appliances.objects.filter(network_type='Internal')
    if appliances_obj:
        for appliance in appliances_obj:
            if appliance.appliance_ip:
                return appliance.appliance_ip
