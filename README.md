# Sophos XGS Firewall → Google SecOps (Chronicle) Parser

Parser CBN personalizado para Google SecOps que procesa logs del firewall **Sophos XGS** en formato JSON normalizado por Bindplane.

## 📋 Arquitectura del Pipeline

```
Sophos XGS (KV syslog UDP)
    │
    ▼ puerto 5144
Python Forwarder (EC2/Wazuh)
    │  • Parsea KV → JSON
    │  • Filtra 45 campos esenciales
    │  • Agrega collector_id
    ▼ puerto 5140
Bindplane Agent
    │  • Parse Key Value → Body
    │  • Forward to Google SecOps
    ▼
Google SecOps (Chronicle)
    │  • Log Type: SOPHOS_FIREWALL_CUSTOM
    │  • CBN Parser custom
    ▼
UDM Events (NETWORK_CONNECTION / GENERIC_EVENT)
```

## 📁 Estructura del Repositorio

```
sophos-secops-parser/
├── README.md
├── parser/
│   └── SOPHOS_FIREWALL_CUSTOM.conf   # Parser CBN para Google SecOps
├── forwarder/
│   └── sophos_forwarder.py            # Python forwarder con filtro
├── docs/
│   ├── PIPELINE.md                    # Documentación del pipeline completo
│   ├── UDM_MAPPING.md                 # Mapeo de campos Sophos → UDM
│   └── TROUBLESHOOTING.md             # Errores comunes y soluciones
└── examples/
    ├── sample_log_firewall.json        # Log de ejemplo: Firewall Rule
    └── sample_log_content_filtering.json # Log de ejemplo: Content Filtering
```

## 🔧 Componentes

### 1. Python Forwarder (`forwarder/sophos_forwarder.py`)

Servicio que corre en el EC2/Wazuh y:
- Escucha en **UDP 5144** los logs KV de Sophos
- Parsea el formato KV a JSON limpio
- **Filtra 45 campos** esenciales (descarta ruido)
- Reenvía JSON a Bindplane en **UDP 5140**

**Campos que conserva:**

| Categoría | Campos |
|-----------|--------|
| Core | timestamp, log_type, log_component, log_subtype, log_id, severity |
| IPs/Puertos | src_ip, dst_ip, src_port, dst_port, src_country, dst_country |
| MACs | src_mac, dst_mac |
| Firewall | fw_rule_id, fw_rule_name, fw_rule_section, fw_rule_type |
| NAT | nat_rule_id, nat_rule_name, src_trans_ip, dst_trans_ip |
| Network | protocol, bytes_sent, bytes_received, packets_sent, packets_received, duration |
| Interfaces | in_interface, out_interface, in_display_interface, out_display_interface |
| Zonas | src_zone, dst_zone, src_zone_type, dst_zone_type |
| Device | device_name, device_model, device_serial_id, collector_id |
| Aplicación | app_name, app_category, app_risk, app_technology, app_resolved_by, app_is_cloud |
| Otros | ether_type, hb_status, qualifier, con_id, con_event, web_policy_id, ips_policy_id |

### 2. CBN Parser (`parser/SOPHOS_FIREWALL_CUSTOM.conf`)

Parser adaptado del parser oficial de Google para Sophos Firewall, modificado para:
- Recibir **JSON** (no KV syslog directo)
- Usar campos del **Body** de Bindplane
- Manejar todos los tipos de log de Sophos XGS

**UDM Fields mapeados:**

| UDM Field | Campo Sophos |
|-----------|-------------|
| `principal.ip` | `src_ip` |
| `principal.port` | `src_port` |
| `principal.mac` | `src_mac` |
| `principal.location.country_or_region` | `src_country` |
| `principal.nat_ip` | `src_trans_ip` |
| `target.ip` | `dst_ip` |
| `target.port` | `dst_port` |
| `target.mac` | `dst_mac` |
| `target.location.country_or_region` | `dst_country` |
| `target.application` | `app_name` |
| `target.url` | `url` |
| `intermediary.hostname` | `device_name` |
| `intermediary.asset.asset_id` | `device_serial_id` |
| `network.ip_protocol` | `protocol` |
| `network.sent_bytes` | `bytes_sent` |
| `network.received_bytes` | `bytes_received` |
| `network.sent_packets` | `packets_sent` |
| `network.received_packets` | `packets_received` |
| `network.session_duration.seconds` | `duration` |
| `network.application_protocol` | Puerto 53→DNS, 80→HTTP, 443→HTTPS |
| `security_result.action` | `log_subtype` (Allowed→ALLOW, Denied→BLOCK) |
| `security_result.rule_name` | `fw_rule_name` |
| `security_result.rule_id` | `fw_rule_id` |
| `security_result.rule_set` | `fw_rule_section` |
| `security_result.rule_type` | `fw_rule_type` |
| `security_result.severity` | `severity` (mappeo a enum UDM) |
| `security_result.summary` | `log_component` + `log_subtype` |
| `security_result.detection_fields` | Todos los demás campos Sophos |

**Event types generados:**

| Condición | event_type |
|-----------|------------|
| Tiene src_ip y dst_ip válidos | `NETWORK_CONNECTION` |
| Invalid Traffic / IPs inválidas | `GENERIC_EVENT` |
| Solo src_ip o src_mac | `STATUS_UPDATE` |

## 🚀 Instalación

### Forwarder en EC2

```bash
# Copiar el forwarder
cp sophos_forwarder.py /opt/sophosfirewall/sophos_forwarder.py
chmod +x /opt/sophosfirewall/sophos_forwarder.py

# Crear servicio systemd
cat > /etc/systemd/system/sophos-forwarder.service << 'EOF'
[Unit]
Description=Sophos Firewall Log Forwarder
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 /opt/sophosfirewall/sophos_forwarder.py
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable sophos-forwarder
systemctl start sophos-forwarder
```

### Parser en Google SecOps

1. Ir a **Settings → Parsers → Create Custom Parser**
2. **Log Type:** `SOPHOS_FIREWALL_CUSTOM`
3. Pegar contenido de `parser/SOPHOS_FIREWALL_CUSTOM.conf`
4. Click **Deploy**

### Bindplane

Configurar el pipeline en Bindplane:
- **Source:** UDP syslog en puerto 5140
- **Processor:** Parse Key Value (campo: `log.record.original`)
- **Destination:** Google Chronicle con log_type `SOPHOS_FIREWALL_CUSTOM`

### Sophos XGS

Configurar syslog en Sophos XGS:
- **Server:** IP del EC2/Wazuh
- **Port:** 5144
- **Protocol:** UDP
- **Format:** Device standard format

## 📊 Ejemplo de Evento UDM Generado

```
metadata.event_type          = "NETWORK_CONNECTION"
metadata.vendor_name         = "Sophos"
metadata.product_name        = "Sophos Firewall"
metadata.description         = "Sophos Content Filtering Application Denied"

principal.ip                 = "172.16.13.155"
principal.port               = 52898
principal.mac                = "ce:00:28:7a:c7:9e"

target.ip                    = "172.64.41.3"
target.port                  = 443
target.application           = "WARP"
target.location.country_or_region = "USA"

network.ip_protocol          = "TCP"
network.application_protocol = "HTTPS"

intermediary.hostname        = "PasadenaFirewall"
intermediary.asset.asset_id  = "ID:X33010YXBYB2Y83"

security_result.action       = "BLOCK"
security_result.rule_name    = "USUARIOS-TO-INTERNET"
security_result.severity     = "INFORMATIONAL"
security_result.summary      = "Sophos Application Denied"
```

## 🐛 Troubleshooting

Ver `docs/TROUBLESHOOTING.md` para errores comunes.

## 📝 Historial de Cambios

| Versión | Fecha | Cambio |
|---------|-------|--------|
| v1.0 | 2026-05-13 | Parser inicial funcional |
| v1.0 | 2026-05-13 | Forwarder con filtro de 45 campos |
| v1.0 | 2026-05-13 | Adaptación parser oficial Google para JSON |

## 🏢 Entorno

- **Firewall:** Sophos XGS3300 (PasadenaFirewall)
- **Serial:** X33010YXBYB2Y83
- **Collector:** FW-LIN-BOG-PAS
- **Namespace:** [LinkTIC]
- **EC2:** Ec2Wazuh (Wazuh + Bindplane)
