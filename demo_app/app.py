from flask import Flask, request
from markupsafe import escape

app = Flask(__name__)


@app.route("/")
def home():
    return """
    <h1>XSSpectra Local Testing Lab</h1>
    <p>This application is for local educational testing only.</p>
    <ul>
        <li><a href="/vulnerable">Vulnerable Reflection Page</a></li>
        <li><a href="/safe">Protected Reflection Page</a></li>
    </ul>
    """


@app.route("/vulnerable")
def vulnerable():
    user_input = request.args.get("q", "")

    return f"""
    <h1>Vulnerable Reflection Demo</h1>
    <p>Input: {user_input}</p>
    <form>
        <input type="text" name="q" placeholder="Enter test text">
        <button type="submit">Submit</button>
    </form>
    """


@app.route("/safe")
def safe():
    user_input = request.args.get("q", "")

    return f"""
    <h1>Protected Reflection Demo</h1>
    <p>Input: {escape(user_input)}</p>
    <form>
        <input type="text" name="q" placeholder="Enter test text">
        <button type="submit">Submit</button>
    </form>
    """


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000)