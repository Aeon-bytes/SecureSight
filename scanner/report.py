from jinja2 import Template

HTML_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Configuration Exposure Scan Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 2em; }
        h1 { color: #2c3e50; }
        .section { margin-bottom: 2em; }
        .risk { color: #c0392b; }
        .advice { color: #2980b9; }
    </style>
</head>
<body>
    <h1>Scan Report for {{ target }}</h1>
    <div class="section">
        <h2>Open Ports</h2>
        {% if ports.open_ports %}
            <p class="risk">Open ports: {{ ports.open_ports|join(', ') }}</p>
            <p class="advice">{{ ports.advice }}</p>
        {% else %}
            <p>No open ports detected or scan failed.</p>
        {% endif %}
    </div>
    <div class="section">
        <h2>SSL/TLS</h2>
        {% if ssl.error %}
            <p>Error: {{ ssl.error }}</p>
        {% else %}
            <p>Subject: {{ ssl.subject }}</p>
            <p>Issuer: {{ ssl.issuer }}</p>
            <p>Expires: {{ ssl.not_after }}</p>
            <p class="advice">{{ ssl.advice }}</p>
        {% endif %}
    </div>
    <div class="section">
        <h2>Web Configuration</h2>
        {% if http.error %}
            <p>Error: {{ http.error }}</p>
        {% else %}
            <ul>
            {% for finding in http.findings %}
                <li class="risk">{{ finding }}</li>
            {% endfor %}
            </ul>
            <p class="advice">{{ http.advice }}</p>
        {% endif %}
    </div>
</body>
</html>
"""

def generate_report(target, results, output_file):
    template = Template(HTML_TEMPLATE)
    html = template.render(target=target, ports=results['ports'], ssl=results['ssl'], http=results['http'])
    with open(output_file, "w") as f:
        f.write(html)
