import io
import json
import zipfile


# ============================================================
# CREATE SECURE MEDICAL PAYLOAD
# ============================================================

def create_medical_payload(
    report_data,
    report_filename,
    xray_data=None,
    xray_filename=None,
    prescription="",
    patient_name="",
    patient_id="",
    age="",
    gender="",
    diagnosis=""
):
    """
    Combines the medical report, X-ray/MRI/CT image,
    prescription and patient information into one ZIP payload.

    This payload will later be encrypted using AES-256-GCM.
    """

    # --------------------------------------------------------
    # Create ZIP package in memory
    # --------------------------------------------------------

    memory_file = io.BytesIO()

    with zipfile.ZipFile(
        memory_file,
        mode="w",
        compression=zipfile.ZIP_DEFLATED
    ) as zip_file:

        # ----------------------------------------------------
        # Patient information
        # ----------------------------------------------------

        patient_information = {
            "patient_name": patient_name,
            "patient_id": patient_id,
            "age": age,
            "gender": gender,
            "diagnosis": diagnosis,
            "prescription": prescription
        }

        zip_file.writestr(
            "patient_information.json",
            json.dumps(
                patient_information,
                indent=4
            )
        )

        # ----------------------------------------------------
        # Medical report
        # ----------------------------------------------------

        if report_data:

            safe_report_filename = (
                report_filename
                if report_filename
                else "medical_report"
            )

            zip_file.writestr(
                f"medical_report/{safe_report_filename}",
                report_data
            )

        # ----------------------------------------------------
        # X-ray / MRI / CT image
        # ----------------------------------------------------

        if xray_data and xray_filename:

            zip_file.writestr(
                f"medical_image/{xray_filename}",
                xray_data
            )

        # ----------------------------------------------------
        # Prescription
        # ----------------------------------------------------

        zip_file.writestr(
            "prescription.txt",
            prescription.encode("utf-8")
        )

    # --------------------------------------------------------
    # Get final ZIP bytes
    # --------------------------------------------------------

    memory_file.seek(0)

    return memory_file.read()


# ============================================================
# EXTRACT SECURE MEDICAL PAYLOAD
# ============================================================

def extract_medical_payload(payload_data):
    """
    Extracts the medical report, X-ray/MRI/CT,
    prescription and patient information from
    the decrypted payload.
    """

    memory_file = io.BytesIO(payload_data)

    with zipfile.ZipFile(
        memory_file,
        mode="r"
    ) as zip_file:

        files = zip_file.namelist()

        # ----------------------------------------------------
        # Patient information
        # ----------------------------------------------------

        patient_information = {}

        if "patient_information.json" in files:

            patient_json = zip_file.read(
                "patient_information.json"
            )

            patient_information = json.loads(
                patient_json.decode("utf-8")
            )

        # ----------------------------------------------------
        # Prescription
        # ----------------------------------------------------

        prescription = ""

        if "prescription.txt" in files:

            prescription = zip_file.read(
                "prescription.txt"
            ).decode("utf-8")

        # ----------------------------------------------------
        # Find medical report
        # ----------------------------------------------------

        report_filename = None
        report_data = None

        for filename in files:

            if filename.startswith(
                "medical_report/"
            ):

                report_filename = filename.split(
                    "medical_report/",
                    1
                )[1]

                report_data = zip_file.read(
                    filename
                )

                break

        # ----------------------------------------------------
        # Find X-ray / MRI / CT
        # ----------------------------------------------------

        xray_filename = None
        xray_data = None

        for filename in files:

            if filename.startswith(
                "medical_image/"
            ):

                xray_filename = filename.split(
                    "medical_image/",
                    1
                )[1]

                xray_data = zip_file.read(
                    filename
                )

                break

    # --------------------------------------------------------
    # Return everything
    # --------------------------------------------------------

    return {
        "patient_information": patient_information,

        "report_filename": report_filename,
        "report_data": report_data,

        "xray_filename": xray_filename,
        "xray_data": xray_data,

        "prescription": prescription
    }