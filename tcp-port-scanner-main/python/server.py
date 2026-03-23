from flask import Flask, request, jsonify, Response
import subprocess, json, os, socket, tempfile, time

app = Flask(__name__)
SCANNER_BIN = os.path.join(os.path.dirname(__file__), '..', 'scanner_main')

def get_source_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except:
        return "0.0.0.0"

@app.route('/api/scan', methods=['POST'])
def run_scan():
    data    = request.get_json()
    target  = data.get('target', '').strip()
    ports   = data.get('ports', '1-1024').strip()
    threads = str(data.get('threads', 100))
    timeout = str(data.get('timeout', 2))
    retries = str(data.get('retries', 1))
    if not target:
        return jsonify({'error': 'Target IP required'}), 400
    try:
        target_ip = socket.gethostbyname(target)
    except socket.gaierror as e:
        return jsonify({'error': f'Cannot resolve: {e}'}), 400
    source_ip = get_source_ip()
    outfile   = tempfile.mktemp(suffix='.json')
    cmd = [
        SCANNER_BIN,
        '--target',  target_ip,
        '--source',  source_ip,
        '--ports',   ports,
        '--threads', threads,
        '--timeout', timeout,
        '--retries', retries,
        '--output',  outfile
    ]
    try:
        start = time.time()
        proc  = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        elapsed = round(time.time() - start, 3)
        result = {}
        if os.path.exists(outfile):
            with open(outfile) as f:
                result = json.load(f)
            os.remove(outfile)
        return jsonify({
            'success': True,
            'target':  target_ip,
            'source':  source_ip,
            'ports':   ports,
            'threads': int(threads),
            'elapsed': elapsed,
            'result':  result,
            'stdout':  proc.stdout
        })
    except subprocess.TimeoutExpired:
        return jsonify({'error': 'Scan timed out'}), 500
    except FileNotFoundError:
        return jsonify({'error': 'scanner_main not found. Run make first.'}), 500
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/containers', methods=['GET'])
def get_containers():
    try:
        proc = subprocess.run(
            ['docker', 'ps', '--format', '{{.Names}}\t{{.Image}}\t{{.Status}}\t{{.Ports}}'],
            capture_output=True, text=True, timeout=10
        )
        containers = []
        for line in proc.stdout.strip().split('\n'):
            if not line:
                continue
            parts = line.split('\t')
            if len(parts) >= 2:
                containers.append({
                    'name':   parts[0],
                    'image':  parts[1],
                    'status': parts[2] if len(parts) > 2 else '',
                    'ports':  parts[3] if len(parts) > 3 else ''
                })
        for c in containers:
            try:
                r = subprocess.run(
                    ['docker', 'inspect', c['name']],
                    capture_output=True, text=True, timeout=5
                )
                info = json.loads(r.stdout)
                nets = info[0]['NetworkSettings']['Networks']
                c['ip'] = list(nets.values())[0].get('IPAddress', '')
            except:
                c['ip'] = ''
        return jsonify({'containers': containers})
    except Exception as e:
        return jsonify({'containers': [], 'error': str(e)})

@app.route('/')
def index():
    ui_path = os.path.join(os.path.dirname(__file__), 'ui.html')
    return Response(open(ui_path).read(), mimetype='text/html')

if __name__ == '__main__':
    print("\n  PortScan UI → http://localhost:5000\n")
    app.run(host='0.0.0.0', port=5000, debug=False)