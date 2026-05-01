from flask import Flask, render_template, request
from phishing import check_phishing
from url_detector import check_url

app = Flask(__name__)


@app.route("/", methods=["GET", "POST"])
def home():

    email_result = None
    url_result = None

    if request.method == "POST":

        if "email_submit" in request.form:

            subject = request.form.get("subject")
            body = request.form.get("body")
            sender = request.form.get("sender")

            score, reasons, ml = check_phishing(subject, body, sender)

            email_result = {
                "score": score,
                "reasons": reasons,
                "ml": ml
            }

        elif "url_submit" in request.form:

            url = request.form.get("url")

            score, reasons, ml = check_url(url)

            url_result = {
                "score": score,
                "reasons": reasons,
                "ml": ml
            }

    return render_template("index.html",
                           email_result=email_result,
                           url_result=url_result)


if __name__ == "__main__":
    app.run(debug=True)