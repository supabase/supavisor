from http.server import BaseHTTPRequestHandler, HTTPServer
import json


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
        "auth": "sbp_04fee3d26b63d9a3557c72a1b9902cbb84100000",
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

        # Build response
        for case in testCases:
            if auth == case.get("auth"):
                resp_code = case.get("response").get("code")
                response_bytes = json.dumps(case.get("response").get("data")).encode(
                    "utf-8"
                )
                break

        print(f"Got connection {auth}")
        # Send response
        self.send_response(resp_code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(response_bytes)))
        self.end_headers()

        self.wfile.write(response_bytes)

    # Silence logging
    def log_message(self, format, *args):
        return


if __name__ == "__main__":
    server = HTTPServer(("0.0.0.0", 8080), SimpleHandler)
    print("Server listening on port 8080")
    server.serve_forever()
