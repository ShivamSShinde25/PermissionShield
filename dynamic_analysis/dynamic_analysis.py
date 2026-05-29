from collections import defaultdict


# -----------------------------------
# Risk Weights
# -----------------------------------

BEHAVIOR_RULES = {

 
    if (
      "CAMERA" in permissions and
      "INTERNET" in permissions
    ):
        suspicious_flags.append(
          "Possible covert camera data transmission"
        )


    if (
      "LOCATION" in permissions and
      "INTERNET" in permissions
    ):
        suspicious_flags.append(
          "Potential GPS tracking with network exfiltration"
        )


    if (
      (
       "CONTACTS" in permissions or
       "READ_CONTACTS" in permissions
      )
      and
      "INTERNET" in permissions
    ):
        suspicious_flags.append(
           "Possible contact exfiltration behavior"
        )


    if (
      "MICROPHONE" in permissions and
      "INTERNET" in permissions
    ):
        suspicious_flags.append(
           "Possible covert audio transmission"
        )



    # --------------------------------
    # Multi-permission anomaly checks
    # --------------------------------

    dangerous_combo=0

    for p in permissions:

        if p in (
          "CAMERA",
          "LOCATION",
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