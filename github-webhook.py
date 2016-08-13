import hashlib
import hmac
import logging
import subprocess
import traceback

import requests
from threading import Thread
from flask import Flask, request, jsonify, Response

latest_build_log = "Nothing build yet.."

# set up logging to file - see previous section for more details
logging.basicConfig(level=logging.DEBUG,
                    format='%(asctime)s %(name)-12s %(levelname)-8s %(message)s',
                    datefmt='%m-%d %H:%M',
                    filename='deployment.log',
                    filemode='w')
# define a Handler which writes INFO messages or higher to the sys.stderr
console = logging.StreamHandler()
console.setLevel(logging.INFO)
# set a format which is simpler for console use
formatter = logging.Formatter('%(name)-12s: %(levelname)-8s %(message)s')
# tell the handler to use this format
console.setFormatter(formatter)
# add the handler to the root logger
logging.getLogger('').addHandler(console)

logger = logging.getLogger("github-webhook")

app = Flask(__name__)


def verify_hmac_hash(data, signature):
    github_secret = bytes('slkjhsdfvjasdvffaskldfkasn23o423kl', 'UTF-8')
    mac = hmac.new(github_secret, msg=data, digestmod=hashlib.sha1)
    return hmac.compare_digest('sha1=' + mac.hexdigest(), signature)


@app.route("/latest_build_log")
def show_latest_log():
    return latest_build_log.replace("\n", "<br/>")


@app.route("/payload", methods=['POST'])
def github_payload():
    try:
        signature = request.headers.get('X-Hub-Signature')
        data = request.data
        if verify_hmac_hash(data, signature):
            if 'X-GitHub-Event' in request.headers:
                if request.headers.get('X-GitHub-Event') == "ping":
                    return jsonify({'msg': 'Ok'})
                if request.headers.get('X-GitHub-Event') == "deployment":
                    payload = request.get_json()
                    logger.info(str(payload))
                    Thread(target=redeploy, args=(payload,)).start()
                    return Response("Starting deployment", mimetype='text/plain')
                else:
                    logger.info(request.headers.get('X-GitHub-Event'))
                    return jsonify({'msg': 'ok thanks for letting me know!'})
            else:
                return jsonify({'msg': 'hmmm somthing is wrong'}), 500
        else:
            return jsonify({'msg': 'invalid hash'})
    except Exception as err:
        traceback.print_exc()


def redeploy(payload):
    update_deployment_status(payload, "pending", "shutting down app")
    result = "shutting down son-editor\n"
    logger.info("shutting down son-editor")
    try:
        res = requests.get('http://localhost:5000/shutdown')
        result += "Response was:" + res.text + "\n"
        logger.info("Response was:" + res.text)
    except Exception as err:
        result += "exception while trying to restart:\n" + str(err) + "\n"
        logger.warning("exception while trying to restart:")
        logger.warning(err)
    result += "starting deployment\n"
    logger.info("starting deployment")
    try:
        update_deployment_status(payload, "pending", "pulling changes")
        result += runProcess(['git', 'stash'])  # saving config
        result += runProcess(['git', 'pull'])
        result += runProcess(['git', 'stash', 'pop'])  # restoring config

        update_deployment_status(payload, "pending", "building app")
        result += runProcess(['python', 'setup.py', 'build'])
        result += runProcess(['python', 'setup.py', 'install'])

        update_deployment_status(payload, "pending", "starting app")
        result += runInBackground(['son-editor'])

        update_deployment_status(payload, "success", "Deployment finished")

    except subprocess.CalledProcessError as error:
        logger.exception("Code deployment failed")
        update_deployment_status(payload, "failure", "Deployment failed, see log for details")
        return jsonify({'msg': str(error.output)})
    except Exception as fail:
        logger.exception("Code deployment failed")
        update_deployment_status(payload, "failure",
                                 "Deployment failed with statuscode {}\nLog:\n{}".format(fail.args[1],
                                                                                         fail.args[0]))
    return result


def update_deployment_status(payload, state, description):
    headers = {"Accept": "application/json",
               "Authorization": "token " + "3341ed2f90c984baaaba90d387affe7a851573b4"}
    requests.post(payload["deployment"]["url"] + "/statuses", json={"state": state, "description": description})


def runInBackground(exe):
    subprocess.Popen(exe)
    return "Starting " + str(exe) + "\n"


def runProcess(exe):
    result = "Running " + str(exe) + "\n"
    p = subprocess.Popen(exe, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    while True:
        retcode = p.poll()  # returns None while subprocess is running
        line = p.stdout.readline()
        try:
            logger.info(line.decode("utf-8"))
            result += line.decode("utf-8")
        except:
            logger.info(line)
            result += str(line) + "\n"
        if retcode is not None:
            logger.info("Returncode: {}".format(retcode))
            result += "Returncode: {}".format(retcode) + "\n"
            break
    if not retcode == 0:
        raise Exception(result, retcode)
    return result


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5050)
