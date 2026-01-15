from flask import Flask, render_template, request
import csv
import io
import pickle
import numpy as np
app = Flask(__name__)
with open("best_model.pkl", "rb") as f:
    loaded_model = pickle.load(f)
# ALL COLUMNS YOU PROVIDED
COLUMNS = [
    
    'R1-PA1:VH',
 'R1-PM1:V',
 'R1-PA2:VH',
 'R1-PM2:V',
 'R1-PA3:VH',
 'R1-PM3:V',
 'R1-PA4:IH',
 'R1-PM4:I',
 'R1-PA5:IH',
 'R1-PM5:I',
 'R1-PA6:IH',
 'R1-PM6:I',
 'R1-PA7:VH',
 'R1-PM7:V',
 'R1-PA8:VH',
 'R1-PM8:V',
 'R1-PA9:VH',
 'R1-PM9:V',
 'R1-PA10:IH',
 'R1-PM10:I',
 'R1-PA11:IH',
 'R1-PM11:I',
 'R1-PA12:IH',
 'R1-PM12:I',
 'R1:F',
 'R1:DF',
 'R1-PA:Z',
 'R1-PA:ZH',
 'R1:S',
 'R2-PA1:VH',
 'R2-PM1:V',
 'R2-PA2:VH',
 'R2-PM2:V',
 'R2-PA3:VH',
 'R2-PM3:V',
 'R2-PA4:IH',
 'R2-PM4:I',
 'R2-PA5:IH',
 'R2-PM5:I',
 'R2-PA6:IH',
 'R2-PM6:I',
 'R2-PA7:VH',
 'R2-PM7:V',
 'R2-PA8:VH',
 'R2-PM8:V',
 'R2-PA9:VH',
 'R2-PM9:V',
 'R2-PA10:IH',
 'R2-PM10:I',
 'R2-PA11:IH',
 'R2-PM11:I',
 'R2-PA12:IH',
 'R2-PM12:I',
 'R2:F',
 'R2:DF',
 'R2-PA:Z',
 'R2-PA:ZH',
 'R2:S',
 'R3-PA1:VH',
 'R3-PM1:V',
 'R3-PA2:VH',
 'R3-PM2:V',
 'R3-PA3:VH',
 'R3-PM3:V',
 'R3-PA4:IH',
 'R3-PM4:I',
 'R3-PA5:IH',
 'R3-PM5:I',
 'R3-PA6:IH',
 'R3-PM6:I',
 'R3-PA7:VH',
 'R3-PM7:V',
 'R3-PA8:VH',
 'R3-PM8:V',
 'R3-PA9:VH',
 'R3-PM9:V',
 'R3-PA10:IH',
 'R3-PM10:I',
 'R3-PA11:IH',
 'R3-PM11:I',
 'R3-PA12:IH',
 'R3-PM12:I',
 'R3:F',
 'R3:DF',
 'R3-PA:Z',
 'R3-PA:ZH',
 'R3:S',
 'R4-PA1:VH',
 'R4-PM1:V',
 'R4-PA2:VH',
 'R4-PM2:V',
 'R4-PA3:VH',
 'R4-PM3:V',
 'R4-PA4:IH',
 'R4-PM4:I',
 'R4-PA5:IH',
 'R4-PM5:I',
 'R4-PA6:IH',
 'R4-PM6:I',
 'R4-PA7:VH',
 'R4-PM7:V',
 'R4-PA8:VH',
 'R4-PM8:V',
 'R4-PA9:VH',
 'R4-PM9:V',
 'R4-PA10:IH',
 'R4-PM10:I',
 'R4-PA11:IH',
 'R4-PM11:I',
 'R4-PA12:IH',
 'R4-PM12:I',
 'R4:F',
 'R4:DF',
 'R4-PA:Z',
 'R4-PA:ZH',
 'R4:S',
 'control_panel_log1',
 'control_panel_log2',
 'control_panel_log3',
 'control_panel_log4',
 'relay1_log',
 'relay2_log',
 'relay3_log',
 'relay4_log',
 'snort_log1',
 'snort_log2',
 'snort_log3',
 'snort_log4'
]
FEATURE_COLUMNS = [col for col in COLUMNS if col not in ["SHA256", "Type"]]

ATTACK_MAP = {
    0: "Attack",
    1: "Natural",
    2: "NoEvents"
  
}




def prediction(input_data):
    """
    input_data: dict {column: value}
    """

    feature_values = []

    for col in FEATURE_COLUMNS:
        val = input_data.get(col, 0)

        # Handle empty strings
        if val in ("", None):
            val = 0

        feature_values.append(float(val))

    # Convert to numpy array (1 sample, n_features)
    X = np.array(feature_values).reshape(1, -1)

    # Predict
    pred_class = loaded_model.predict(X)[0]

    return ATTACK_MAP.get(int(pred_class), "Unknown")


@app.route("/")
def index():
    return render_template("index.html", columns=COLUMNS)


@app.route("/submit", methods=["POST"])
def submit():
    table_data = []

    # ---------- MANUAL INPUT ----------
    manual_row = {}
    filled = False

    for col in COLUMNS:
        value = request.form.get(col)
        if value:
            filled = True
        manual_row[col] = value

    if filled:
        manual_row["Prediction"] = prediction(manual_row)
        table_data.append(manual_row)

    # ---------- FILE UPLOAD ----------
    file = request.files.get("file")
    if file and file.filename.endswith(".csv"):
        stream = io.StringIO(file.stream.read().decode("utf-8"))
        reader = csv.DictReader(stream)

        for row in reader:
            row["Prediction"] = prediction(row)
            table_data.append(row)

    return render_template(
        "result.html",
        columns=COLUMNS + ["Prediction"],
        rows=table_data
    )



if __name__ == "__main__":
    app.run(debug=True)
