from collections import defaultdict


# -----------------------------------
# Risk Weights
# -----------------------------------


          "MICROPHONE",
          "CONTACTS",
          "READ_CONTACTS"
        ):
            dangerous_combo+=1


    if dangerous_combo>=3:
        suspicious_flags.append(
         "Multiple sensitive permissions indicate anomalous runtime behavior"
        )



    return suspicious_flags




# -----------------------------------
# Optional Dynamic Risk Score
# -----------------------------------

def calculate_dynamic_risk(flags):

    score=len(flags)*20

    if score<30:
        level="LOW"

    elif score<60:
        level="MEDIUM"

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