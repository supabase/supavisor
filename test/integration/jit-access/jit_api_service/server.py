import json
import logging
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer

# Configure logging for Docker (outputs to stdout/stderr)
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout)
    ],
    force=True
)

logger = logging.getLogger(__name__)

testCases = [
    {
        "auth": "sbp_04fee3d26b63d9a3557c72a1b9902cbb8412c836",
        "expected_role": "postgres",
        "response": {
            "code": 200,
            "data": {
                "user_id": "087f4b1c-da1c-4172-92c5-1ace925079ea",
                "user_role": {"role": "postgres"},
            },
        },
    },
    {
        "auth": "sbp_04fee3d26b63d9a3557c72a1b9902cbb8412c000",
        "expected_role": "postgres",
        "response": {
            "code": 200,
            "data": {
                "user_id": "087f4b1c-da1c-4172-92c5-1ace925079ea",
                "user_role": {"role": "otherrole"},
            },
        },
    },
    {
        "auth": "sbp_04fee3d26b63d9a3557c72a1b9902cbb84100001",
        "expected_role": "supabase_admin",
        "response": {"code": 403, "data": ""},
    },
]


class SimpleHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        # Read Authorization header
        auth = self.headers.get("Authorization").replace("Bearer ", "")

        # Read body
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length).decode("utf-8")

        try:
            data = json.loads(body)
        except json.JSONDecodeError:
            self.send_response(400)
            self.end_headers()
            self.wfile.write(b'{"error":"invalid JSON"}')
            return

        resp_code = 401  # default
        response_bytes = json.dumps({"message": "failed authorization"}).encode()

        logger.info(f"POST request from {self.client_address[0]} - Auth token: {auth[:10]}, Data: {json.dumps(data)}")
        # Build response
        for case in testCases:
            if auth == case.get("auth"):
                resp_code = case.get("response").get("code")
                response_bytes = json.dumps(case.get("response").get("data")).encode(
                    "utf-8"
                )
                logger.info(f"Auth test case {auth} - ResponseCode: {resp_code}, ResponseData: {response_bytes}")
                break

        # Send response
        self.send_response(resp_code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(response_bytes)))
        self.end_headers()

        self.wfile.write(response_bytes)

    def do_GET(self):
        if self.path == "/health":
            logger.info(f"GET health from {self.client_address[0]}")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"status":"healthy"}')

    # Silence logging
    def log_message(self, format, *args):
        return


if __name__ == "__main__":
    server = HTTPServer(("0.0.0.0", 8080), SimpleHandler)
    print("Server listening on port 8080")
    server.serve_forever()
