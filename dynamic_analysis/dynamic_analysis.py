from collections import defaultdict


# -----------------------------------
# Risk Weights
# -----------------------------------

BEHAVIOR_RULES = {

 "CAMERA":{
   "flag":"Possible covert camera activity",
   "weight":25
 },

 "LOCATION":{
   "flag":"Potential location tracking behavior",
   "weight":30
 },

 "MICROPHONE":{
   "flag":"Potential microphone surveillance",
   "weight":35
 },

 "CONTACTS":{
   "flag":"Sensitive contact harvesting",
   "weight":35
 },

 "READ_CONTACTS":{
   "flag":"Sensitive contact harvesting",
   "weight":35
 },

 "INTERNET":{
   "flag":None,
   "weight":5
 }

}



# 

    else:
        level="HIGH"

    return score,level




if __name__=="__main__":

    sample_permissions=[
       "CAMERA",
       "LOCATION",
       "INTERNET",
       "CONTACTS"
    ]

    flags=simulate_dynamic_analysis(
       sample_permissions
    )

    print(
       flags
    )