import subprocess
import os
import shutil
import xml.etree.ElementTree as ET


def extract_permissions(apk_path):

    try:
        output_dir = "temp_apk"

        # ----------------------------------
        # Clean previous extraction
        # ----------------------------------

        if os.path.exists(output_dir):
            shutil.rmtree(output_dir, ignore_errors=True)


        print("Extracting APK file...")
        print(f"APK Path: {apk_path}")

        apktool_jar_path = r"C:\apktool\apktool.jar"

        command = (
            f'java -Xmx2G -jar "{apktool_jar_path}" '
            f'd "{apk_path}" -o "{output_dir}" -f'
        )

        print(f"Running command: {command}")

        result = subprocess.run(
            command,
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )


        # ----------------------------------
        # Verify APKTool execution
        # ----------------------------------

        if result.returncode != 0:
            print("STDOUT:", result.stdout)
            print("STDERR:", result.stderr)
            raise Exception("APKTool execution failed.")



        # ----------------------------------
        # Locate Android Manifest
        # ----------------------------------

        manifest_path = os.path.join(
            output_dir,
            "AndroidManifest.xml"
        )

        permissions = []


        if os.path.exists(manifest_path):

            tree = ET.parse(manifest_path)
            root = tree.getroot()

            android_ns = (
                "{http://schemas.android.com/apk/res/android}name"
            )

            # Support multiple Android permission tags
            permission_tags = [
                ".//uses-permission",
                ".//uses-permission-sdk-23",
                ".//uses-permission-sdk-m"
            ]

            seen = set()


            # ----------------------------------
            # Extract permissions
            # ----------------------------------

            for tag in permission_tags:

                for elem in root.findall(tag):

                    permission = elem.get(android_ns)

                    if permission:

                        perm_name = (
                            permission.split(".")[-1].upper()
                        )

                        if perm_name not in seen:
                            seen.add(perm_name)
                            permissions.append(
                                perm_name
                            )


            # ----------------------------------
            # Diagnostics
            # ----------------------------------

            if not permissions:
                print(
                    "[Warning] Manifest parsed "
                    "but no permissions found."
                )

            else:
                print(
                    f"Extracted Permissions: "
                    f"{permissions}"
                )

        else:
            raise FileNotFoundError(
                "AndroidManifest.xml not found in extracted APK."
            )



        # ----------------------------------
        # Cleanup temp extraction
        # ----------------------------------

        shutil.rmtree(
            output_dir,
            ignore_errors=True
        )

        return sorted(permissions)



    except Exception as e:

        print(
            "Error during Static Analysis:",
            e
        )

        # Safe cleanup even on failure
        if os.path.exists("temp_apk"):
            shutil.rmtree(
                "temp_apk",
                ignore_errors=True
            )

        return []