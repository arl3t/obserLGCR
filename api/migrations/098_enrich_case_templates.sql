-- =============================================================================
-- Migration 098 — Enriquecimiento de plantillas DFIR (case_templates)
-- =============================================================================
-- Enriquece el CONTENIDO de las plantillas built-in (checklists de tareas por
-- fase NIST 800-61) tomando como INSPIRACIÓN la estructura de los IRP de
-- SOCFortress (Phishing/Malware/Ransom/AccountCompromised/DataLoss), pero
-- adaptado a NUESTRAS herramientas: Wazuh (aislamiento de agente, FIM, logs de
-- autenticación), FortiGate (bloqueo IP/dominio/URL, webfilter, IPS), MISP,
-- enriquecimiento de IOC (VT/AbuseIPDB/GreyNoise/ThreatFox/OTX/Spamhaus/URLhaus),
-- watchlist saliente (lgcrBL), supresiones y caza externa.
--
-- Además:
--   - Pobla `trigger_mitre_tactics` en las built-in (028 lo dejó vacío → la
--     recomendación por táctica de suggestTemplate() nunca disparaba).
--   - Agrega una plantilla dedicada de RANSOMWARE (TA0040), tapando el hueco de
--     la táctica Impact (ninguna built-in la cubría) — espejo de IRP-Ransom.
--
-- Idempotente: UPDATE reescribe el contenido al valor enriquecido; el INSERT
-- nuevo usa ON CONFLICT DO NOTHING. Sólo afecta plantillas built-in.
-- NOTA: las plantillas se aplican al ABRIR el caso (applyTemplateToCase es
-- idempotente), así que el contenido enriquecido aplica a casos NUEVOS; los
-- casos que ya tenían tareas conservan las suyas.
-- =============================================================================

-- ── tpl_phishing ────────────────────────────────────────────────────────────
UPDATE case_templates SET
  description = 'Phishing, spear-phishing y ataques por correo. Enfocado en alcance del envío, neutralizacion del remitente y saneo de cuentas afectadas.',
  trigger_categories = ARRAY['UNAUTHORIZED_ACCESS','MALICIOUS_CODE','FRAUD'],
  trigger_mitre_tactics = ARRAY['TA0001'],
  tasks_template = '[
    {"title":"Confirmar alcance del envio","description":"Identificar todos los destinatarios, asunto, remitente y headers del correo. Buscar en Wazuh y en el gateway de correo cuantas copias se entregaron y quienes interactuaron.","phase":"DETECTION"},
    {"title":"Extraer y enriquecer IOCs","description":"Sacar dominio del remitente, URLs y hashes de adjuntos. Enriquecer con VirusTotal, URLhaus, OpenPhish y Spamhaus; cruzar con MISP. Documentar veredicto por fuente.","phase":"DETECTION"},
    {"title":"Bloquear remitente, dominio y URL","description":"Cargar el dominio/URL malicioso en el webfilter y la politica de FortiGate, y en las listas de bloqueo del gateway de correo. Sumar dominios C2 a la watchlist saliente (lgcrBL).","phase":"CONTAINMENT"},
    {"title":"Sanear cuentas que interactuaron","description":"Para usuarios que hicieron click o entregaron credenciales: forzar reset de contrasena, revocar sesiones/tokens y habilitar MFA.","phase":"CONTAINMENT"},
    {"title":"Eliminar el correo y reglas maliciosas","description":"Purgar el correo de todos los buzones. Revisar reglas de reenvio/forward automatico creadas por el atacante.","phase":"ERADICATION"},
    {"title":"Analizar payload en sandbox","description":"Detonar adjunto/enlace en entorno aislado. Documentar IOCs adicionales (C2, droppers, persistencia) y publicarlos a MISP / Telegram CTI.","phase":"ERADICATION"},
    {"title":"Limpiar artefactos en endpoints","description":"Buscar y eliminar descargas, claves de registro y tareas programadas en los hosts afectados usando Wazuh FIM y la telemetria del endpoint.","phase":"ERADICATION"},
    {"title":"Restaurar acceso saneado","description":"Re-habilitar las cuentas limpias con MFA y verificar integridad de datos y buzon.","phase":"RECOVERY"},
    {"title":"Validar que el bloqueo no rompe trafico legitimo","description":"Confirmar que los dominios/URLs bloqueados no afectan servicios de negocio. Ajustar reglas si hay falsos positivos.","phase":"RECOVERY"},
    {"title":"Lecciones aprendidas y concientizacion","description":"Documentar vector de entrada, controles que fallaron y mejoras. Notificar/concientizar a los usuarios afectados.","phase":"POST_INCIDENT"}
  ]'::jsonb,
  updated_at = now()
WHERE id = 'tpl_phishing' AND is_builtin;

-- ── tpl_malware ─────────────────────────────────────────────────────────────
UPDATE case_templates SET
  name = 'Malware / Troyano / Backdoor',
  description = 'Infecciones de malware: troyanos, backdoors, loaders y C2. Para ransomware usar la plantilla dedicada.',
  trigger_categories = ARRAY['MALICIOUS_CODE'],
  trigger_mitre_tactics = ARRAY['TA0002','TA0003','TA0011'],
  tasks_template = '[
    {"title":"Identificar binario y enriquecer","description":"Capturar hash SHA-256 del ejecutable, ruta y proceso padre. Enriquecer con VirusTotal, ThreatFox y MISP. Revisar la regla Wazuh y la tecnica MITRE asociada.","phase":"DETECTION"},
    {"title":"Determinar alcance de la infeccion","description":"Buscar el mismo hash/IOC en otros endpoints (Wazuh FIM y caza interna). Revisar logs de red para movimiento lateral o beaconing C2.","phase":"DETECTION"},
    {"title":"Aislar el endpoint infectado","description":"Aislar el agente via Wazuh active response o mover a VLAN de cuarentena. No apagar si se requiere memoria volatil.","phase":"CONTAINMENT"},
    {"title":"Preservar imagen forense","description":"Capturar imagen de disco y volcado de RAM antes de cualquier limpieza, manteniendo cadena de custodia.","phase":"CONTAINMENT"},
    {"title":"Bloquear infraestructura C2","description":"Bloquear IPs/dominios C2 en FortiGate (politica + webfilter) y sumarlos a la watchlist saliente (lgcrBL).","phase":"CONTAINMENT"},
    {"title":"Erradicar binario y persistencia","description":"Eliminar el ejecutable y mecanismos de persistencia (servicios, tareas programadas, run keys). Reimaginar el host si no es recuperable con confianza.","phase":"ERADICATION"},
    {"title":"Actualizar defensas con los IOCs","description":"Cargar firmas/IOCs en Wazuh, IPS de FortiGate y EDR. Publicar el set de IOCs a MISP.","phase":"ERADICATION"},
    {"title":"Restaurar desde backup verificado","description":"Restaurar datos desde un backup previo a la infeccion y validar integridad.","phase":"RECOVERY"},
    {"title":"Monitoreo elevado 30 dias","description":"Mantener vigilancia reforzada sobre el host y las cuentas relacionadas durante 30 dias.","phase":"RECOVERY"},
    {"title":"Lecciones aprendidas e informe ejecutivo","description":"Documentar linea de tiempo, vector inicial, impacto y mejoras. Generar informe ejecutivo del caso.","phase":"POST_INCIDENT"}
  ]'::jsonb,
  updated_at = now()
WHERE id = 'tpl_malware' AND is_builtin;

-- ── tpl_cred_compromise ─────────────────────────────────────────────────────
UPDATE case_templates SET
  description = 'Acceso no autorizado por credenciales: brute-force, password-spray, credential stuffing y uso de cuentas validas.',
  trigger_categories = ARRAY['UNAUTHORIZED_ACCESS'],
  trigger_mitre_tactics = ARRAY['TA0006','TA0008'],
  tasks_template = '[
    {"title":"Identificar cuentas e IPs atacantes","description":"Revisar logs de autenticacion en Wazuh (data.win.eventdata, fallos repetidos, password-spray). Enriquecer la IP atacante con AbuseIPDB, GreyNoise y Spamhaus.","phase":"DETECTION"},
    {"title":"Determinar si hubo acceso exitoso","description":"Confirmar si alguna cuenta autentico con exito y si hubo movimiento lateral o escalada de privilegios posterior.","phase":"DETECTION"},
    {"title":"Revocar sesiones y tokens","description":"Invalidar todas las sesiones y tokens activos de las cuentas afectadas.","phase":"CONTAINMENT"},
    {"title":"Bloquear IPs de origen","description":"Cargar las IPs atacantes en el firewall FortiGate y en la watchlist saliente. Aplicar lockout temporal si corresponde.","phase":"CONTAINMENT"},
    {"title":"Resetear credenciales y forzar MFA","description":"Forzar cambio de contrasena y habilitar MFA en todas las cuentas comprometidas.","phase":"ERADICATION"},
    {"title":"Auditar accesos del periodo comprometido","description":"Revisar a que sistemas y datos accedio la cuenta durante la ventana de compromiso.","phase":"ERADICATION"},
    {"title":"Buscar persistencia","description":"Buscar tokens de API, claves SSH, reglas de buzon, cuentas nuevas o privilegios escalados dejados por el atacante.","phase":"ERADICATION"},
    {"title":"Restaurar acceso controlado","description":"Re-habilitar el acceso con MFA y monitoreo elevado sobre las cuentas.","phase":"RECOVERY"},
    {"title":"Reforzar politica de contrasena/lockout","description":"Validar y endurecer politicas de complejidad, expiracion y bloqueo por intentos fallidos.","phase":"RECOVERY"},
    {"title":"Informe de impacto y notificacion","description":"Documentar que informacion fue expuesta y evaluar notificacion regulatoria.","phase":"POST_INCIDENT"}
  ]'::jsonb,
  updated_at = now()
WHERE id = 'tpl_cred_compromise' AND is_builtin;

-- ── tpl_data_breach ─────────────────────────────────────────────────────────
UPDATE case_templates SET
  description = 'Exfiltracion de datos sensibles o acceso no autorizado a informacion confidencial.',
  trigger_categories = ARRAY['UNAUTHORIZED_ACCESS'],
  trigger_mitre_tactics = ARRAY['TA0010','TA0009'],
  tasks_template = '[
    {"title":"Confirmar y cuantificar la exfiltracion","description":"Determinar volumen, tipo y clasificacion de los datos exfiltrados.","phase":"DETECTION"},
    {"title":"Identificar el canal de salida","description":"Analizar trafico de egress en FortiGate, DNS (posible tunneling) y HTTP/S para determinar el metodo y destino. Enriquecer el destino externo con la intel disponible.","phase":"DETECTION"},
    {"title":"Contener al actor de amenaza","description":"Revocar accesos, bloquear IPs/dominios de exfiltracion en FortiGate + watchlist saliente, cerrar sesiones activas.","phase":"CONTAINMENT"},
    {"title":"Notificar a legal y DPO","description":"Iniciar el proceso de notificacion regulatoria si aplica (GDPR/LOPDGDD u equivalente local).","phase":"CONTAINMENT"},
    {"title":"Preservar evidencia forense","description":"Capturar logs, capturas de red y estados del sistema sin alterarlos, con cadena de custodia.","phase":"CONTAINMENT"},
    {"title":"Cerrar el vector de exfiltracion","description":"Eliminar el canal o vulnerabilidad usada (cuenta, servicio expuesto, regla de salida).","phase":"ERADICATION"},
    {"title":"Reforzar controles de salida y DLP","description":"Revisar y endurecer reglas de egress en FortiGate y controles DLP en endpoints y gateways.","phase":"RECOVERY"},
    {"title":"Notificacion regulatoria","description":"Preparar y enviar la notificacion a las autoridades de proteccion de datos si corresponde.","phase":"POST_INCIDENT"},
    {"title":"Informe forense completo","description":"Generar informe tecnico y ejecutivo con linea de tiempo y cadena de custodia documentada.","phase":"POST_INCIDENT"}
  ]'::jsonb,
  updated_at = now()
WHERE id = 'tpl_data_breach' AND is_builtin;

-- ── tpl_generic ─────────────────────────────────────────────────────────────
UPDATE case_templates SET
  description = 'Plantilla base para cualquier incidente. Sigue el ciclo NIST 800-61 sin asumir un tipo de amenaza.',
  tasks_template = '[
    {"title":"Confirmar el incidente","description":"Verificar que la alerta no es un falso positivo. Revisar evidencia inicial, regla y severidad; descartar ruido conocido (supresiones).","phase":"DETECTION"},
    {"title":"Enriquecer los IOCs","description":"Enriquecer los indicadores (IP/dominio/hash) con las fuentes de intel disponibles y cruzar con MISP.","phase":"DETECTION"},
    {"title":"Determinar el alcance","description":"Identificar todos los sistemas, usuarios e IOCs afectados.","phase":"DETECTION"},
    {"title":"Aplicar contencion","description":"Aislar sistemas comprometidos (Wazuh active response) y bloquear infraestructura maliciosa en FortiGate para evitar propagacion.","phase":"CONTAINMENT"},
    {"title":"Erradicar la amenaza","description":"Remover malware, accesos no autorizados y artefactos maliciosos. Cerrar el vector de entrada.","phase":"ERADICATION"},
    {"title":"Restaurar la operacion","description":"Verificar integridad de los sistemas y restaurar servicios a operacion normal.","phase":"RECOVERY"},
    {"title":"Lecciones aprendidas","description":"Registrar causa raiz, linea de tiempo e impacto. Identificar mejoras de deteccion y respuesta.","phase":"POST_INCIDENT"}
  ]'::jsonb,
  updated_at = now()
WHERE id = 'tpl_generic' AND is_builtin;

-- ── tpl_ransomware (NUEVA — TA0040 Impact) ──────────────────────────────────
INSERT INTO case_templates
  (id, name, description, trigger_categories, trigger_severities,
   mitre_tactics, trigger_mitre_tactics, default_tags, tasks_template, is_builtin, created_by)
VALUES
(
  'tpl_ransomware',
  'Ransomware / Cifrado',
  'Cifrado de datos por ransomware, con o sin doble extorsion (exfiltracion previa). Prioriza aislamiento rapido y restauracion desde backup offline.',
  ARRAY['MALICIOUS_CODE','AVAILABILITY'],
  ARRAY['CRITICAL','HIGH'],
  ARRAY['TA0040','TA0011'],
  ARRAY['TA0040'],
  ARRAY['ransomware','impacto','cifrado','backup'],
  '[
    {"title":"Confirmar cifrado e identificar familia","description":"Verificar extensiones cifradas y nota de rescate. Identificar la familia de ransomware (nota, extension, MISP) para conocer su comportamiento.","phase":"DETECTION"},
    {"title":"Determinar alcance y vector inicial","description":"Mapear hosts y shares cifrados. Identificar el vector de entrada (phishing, RDP expuesto, vulnerabilidad) y si hubo exfiltracion previa (doble extorsion).","phase":"DETECTION"},
    {"title":"Aislar todos los hosts afectados","description":"Aislar de inmediato cada host cifrado via Wazuh active response o apagado de NIC. Deshabilitar shares de red para frenar la propagacion. No apagar si se necesita memoria volatil con posibles claves.","phase":"CONTAINMENT"},
    {"title":"Preservar muestras y evidencia","description":"Conservar la nota de rescate, una muestra del binario y una imagen forense antes de cualquier limpieza.","phase":"CONTAINMENT"},
    {"title":"Bloquear C2 e infraestructura de exfiltracion","description":"Bloquear IPs/dominios de C2 y de exfiltracion en FortiGate y en la watchlist saliente.","phase":"CONTAINMENT"},
    {"title":"Erradicar binario y persistencia","description":"Eliminar el ejecutable y la persistencia; reimaginar los hosts cifrados. Cerrar el vector inicial (parchear/quitar exposicion RDP).","phase":"ERADICATION"},
    {"title":"Restaurar desde backup offline verificado","description":"Restaurar desde backups offline previos al cifrado, validando que no esten cifrados ni comprometidos antes de reconectar.","phase":"RECOVERY"},
    {"title":"Politica de no pago y coordinacion","description":"Aplicar la politica de NO pago del rescate. Coordinar con direccion, legal y aseguradora; evaluar notificacion a autoridades.","phase":"RECOVERY"},
    {"title":"Notificacion regulatoria si hubo exfiltracion","description":"Si hubo robo de datos, preparar la notificacion regulatoria correspondiente.","phase":"POST_INCIDENT"},
    {"title":"Informe ejecutivo y lecciones aprendidas","description":"Documentar linea de tiempo, impacto al negocio, brechas de backup/segmentacion y mejoras. Generar informe ejecutivo.","phase":"POST_INCIDENT"}
  ]'::jsonb,
  true, 'system'
)
ON CONFLICT (id) DO NOTHING;
