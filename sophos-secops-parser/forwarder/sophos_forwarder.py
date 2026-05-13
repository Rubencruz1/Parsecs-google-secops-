#!/usr/bin/env python3
import socket
import sys
import time
import logging
import threading
import re
import json
from datetime import datetime

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/var/log/sophos-forwarder.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

class SophosForwarder:
    def __init__(self):
        self.stats = {'received': 0, 'sent': 0, 'errors': 0, 'dropped': 0}
        self.running = False
        
        # Campos que MANTENER (whitelist)
        self.keep_fields = {
            # Core
            'timestamp', 'log_type', 'log_component', 'log_subtype', 'log_id', 'log_version',
            'severity', 'log_occurrence',
            
            # IPs y puertos
            'src_ip', 'dst_ip', 'src_port', 'dst_port',
            'src_country', 'dst_country',
            
            # MACs
            'src_mac', 'dst_mac',
            
            # Firewall rules
            'fw_rule_id', 'fw_rule_name', 'fw_rule_section', 'fw_rule_type',
            'nat_rule_id', 'nat_rule_name',
            
            # Network
            'protocol', 'bytes_sent', 'bytes_received', 'packets_sent', 'packets_received',
            'duration',
            
            # Interfaces
            'in_interface', 'out_interface', 'in_display_interface', 'out_display_interface',
            'src_zone', 'dst_zone', 'src_zone_type', 'dst_zone_type',
            
            # Device/Firewall
            'device_name', 'device_model', 'device_serial_id', 'collector_id',
            
            # NAT/Translation
            'src_trans_ip', 'dst_trans_ip', 'src_trans_port', 'dst_trans_port',
            
            # Application
            'app_name', 'app_category', 'app_risk', 'app_technology',
            'app_resolved_by', 'app_is_cloud', 'app_filter_policy_id',
            
            # Otros
            'ether_type', 'hb_status', 'qualifier', 'con_id', 'con_event',
            'gw_id_request', 'gw_name_request',
            'web_policy_id', 'ips_policy_id',
        }
    
    def start(self):
        self.running = True
        logger.info("="*80)
        logger.info("Sophos Firewall Forwarder v3 - KV to JSON + FILTER")
        logger.info("Escuchando en 0.0.0.0:5144")
        logger.info(f"Filtrando: mantener {len(self.keep_fields)} campos importantes")
        logger.info("Reenviando a localhost:5140 (Bindplane)")
        logger.info("="*80)
        
        receiver_thread = threading.Thread(target=self._receiver_udp, daemon=True)
        receiver_thread.start()
        
        stats_thread = threading.Thread(target=self._log_stats, daemon=True)
        stats_thread.start()
        
        try:
            while self.running:
                time.sleep(1)
        except KeyboardInterrupt:
            logger.info("Deteniendo...")
            self.running = False
            time.sleep(1)
    
    def _parse_kv_to_dict(self, kv_string):
        """Parsea KV a diccionario"""
        result = {}
        
        # Patrón para key="value" (quoted)
        quoted_pattern = r'(\w+)="([^"]*)"'
        for match in re.finditer(quoted_pattern, kv_string):
            key = match.group(1)
            value = match.group(2)
            result[key] = value
        
        # Patrón para key=value (unquoted)
        unquoted_pattern = r'(\w+)=([^\s"]+)'
        for match in re.finditer(unquoted_pattern, kv_string):
            key = match.group(1)
            value = match.group(2)
            if key not in result:
                result[key] = value
        
        return result
    
    def _filter_fields(self, kv_dict):
        """
        Filtra el diccionario: mantiene solo campos en whitelist
        Retorna: (dict_filtrado, count_dropped)
        """
        filtered = {}
        dropped = 0
        
        for key, value in kv_dict.items():
            if key in self.keep_fields:
                filtered[key] = value
            else:
                dropped += 1
        
        return filtered, dropped
    
    def _kv_to_json(self, kv_message):
        """
        Convierte KV de Sophos a JSON filtrado.
        """
        try:
            # Remover <PRI>
            kv_message = re.sub(r'^<\d+>', '', kv_message)
            
            # Parsear KV a dict
            kv_dict = self._parse_kv_to_dict(kv_message)
            
            # FILTRAR: mantener solo campos importantes
            filtered_dict, dropped = self._filter_fields(kv_dict)
            self.stats['dropped'] += dropped
            
            # Validar timestamp
            if 'timestamp' not in filtered_dict:
                logger.warning(f"Log sin timestamp (drop: {dropped})")
                filtered_dict['timestamp'] = datetime.utcnow().isoformat() + 'Z'
            
            # Convertir a JSON
            json_output = json.dumps(filtered_dict)
            return json_output
        
        except Exception as e:
            logger.error(f"Error parsing KV: {e}")
            return None
    
    def _receiver_udp(self):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind(("0.0.0.0", 5144))
            logger.info("UDP escuchando en puerto 5144")
            
            while self.running:
                try:
                    data, addr = sock.recvfrom(4096)
                    self.stats['received'] += 1
                    
                    message_str = data.decode('utf-8', errors='ignore')
                    
                    # Convertir KV a JSON (con filtro)
                    json_message = self._kv_to_json(message_str)
                    
                    if json_message:
                        if self._send_to_bindplane(json_message.encode('utf-8')):
                            self.stats['sent'] += 1
                            if self.stats['sent'] % 10 == 0:
                                logger.debug(f"Sample: {json_message[:120]}...")
                        else:
                            self.stats['errors'] += 1
                    else:
                        self.stats['errors'] += 1
                
                except Exception as e:
                    self.stats['errors'] += 1
                    logger.error(f"Error procesando log: {e}")
        
        except Exception as e:
            logger.error(f"Error servidor UDP: {e}")
        finally:
            sock.close()
    
    def _send_to_bindplane(self, data):
        """Envía JSON a Bindplane"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.sendto(data, ("localhost", 5140))
            sock.close()
            return True
        except Exception as e:
            logger.error(f"Error enviando a Bindplane: {e}")
            return False
    
    def _log_stats(self):
        """Log de estadísticas cada minuto"""
        while self.running:
            time.sleep(60)
            logger.info(f"Stats - Recibidos: {self.stats['received']}, Enviados: {self.stats['sent']}, "
                       f"Errores: {self.stats['errors']}, Campos eliminados: {self.stats['dropped']}")

if __name__ == '__main__':
    forwarder = SophosForwarder()
    forwarder.start()
