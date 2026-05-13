# Troubleshooting - Sophos XGS → Google SecOps

Errores encontrados durante el desarrollo del parser y sus soluciones.

## Errores CBN Language

### `"timestamp" not found in state data`
**Causa:** En CBN, un `if [campo]` explota si el campo no existe en el log.
**Solución:** Inicializar todos los campos con `replace => { "campo" => "" }` antes de usarlos en condicionales.

### `copy source field must not be empty`
**Causa:** `copy` requiere que el campo destino exista previamente.
**Solución:** Usar `replace` para inicializar el campo destino antes del `copy`, o usar `replace => { "destino" => "%{fuente}" }` directamente.

### `merge source field must not be empty`
**Causa:** `merge` falla si el campo fuente está vacío.
**Solución:** Proteger con `if [campo] != ""` (solo funciona si el campo fue inicializado previamente con `replace`).

### `received non-slice or non-array raw output for repeated field`
**Causa:** Campos `repeated` en el proto UDM (`security_result`, `intermediary`) no se pueden asignar directamente.
**Solución:** Construir un objeto temporal (`_security_result`, `_intermediary`) y luego hacer `merge` al UDM.

### `no descriptor found` en `security_result[0]`
**Causa:** CBN no acepta la sintaxis `campo[0]` para `replace` en campos repeated.
**Solución:** Usar objeto temporal + `merge` al final.

### `field not set` en `replace => { "campo" => "%{otro_campo}" }`
**Causa:** El campo interpolado `%{otro_campo}` no existe en state data.
**Solución:** Inicializar todos los campos usados en interpolación con `replace => { "campo" => "" }` al inicio.

### `if [campo] in ["a","b"]` no soportado
**Causa:** El operador `in` con arrays no está soportado en CBN.
**Solución:** Usar `if [campo] == "a" or [campo] == "b"`.

### `repeated option "merge"` en mismo bloque `mutate`
**Causa:** No se puede usar `merge` más de una vez en el mismo bloque `mutate`.
**Solución:** Separar cada `merge` en su propio bloque `mutate`.

---

## Errores de Timestamp

### `time = 1970-01-01T00:00:00Z`
**Causa:** Bindplane tenía un procesador "Parse Timestamp" apuntando a `con_id` (un número grande como Unix epoch).
**Solución:** Eliminar ese procesador en Bindplane y agregar uno nuevo apuntando al campo `timestamp` con formato ISO8601.

### `time = 2090-03-21T...`
**Causa:** El campo `con_id` (ej: `3793781925`) siendo interpretado como Unix epoch en segundos.
**Solución:** Mismo que arriba — eliminar el procesador de Bindplane que usaba `con_id`.

---

## Errores de UDM Proto

### `received non-map raw output for sub-message field` en `event_timestamp`
**Causa:** `event_timestamp` es un submensaje proto (`Timestamp`), no un string.
**Solución:** No asignar manualmente `event_timestamp`. SecOps lo mapea automáticamente desde el campo `time` del evento que Bindplane setea. Usar el plugin `date {}` de CBN para parsearlo desde el campo `timestamp`.

### `invalid client device: device is empty`
**Causa:** El evento `NETWORK_CONNECTION` requiere al menos una IP o hostname válido en `principal` y `target`.
**Solución:** Asegurar que siempre haya un valor en `principal.hostname` como fallback cuando no hay `src_ip`.

### `field backstory.Noun.ip[0] "" does not match type IP`
**Causa:** El campo `principal.ip` o `target.ip` tiene un valor vacío `""`.
**Solución:** Solo hacer `merge` de IPs dentro de un `if [campo] != ""`.

---

## Errores de Pipeline

### Logs llegan sin campos en Body (todo en `log.record.original`)
**Causa:** Bindplane no está parseando el KV correctamente.
**Solución:** Verificar que el procesador "Parse Key Value" en Bindplane apunta a `log.record.original` (Attributes) y no a Body.

### `metadata.event_type = "GENERIC_EVENT"` cuando debería ser `NETWORK_CONNECTION`
**Causa:** Las IPs no están disponibles cuando se evalúa el event_type.
**Solución:** Mover la determinación del event_type al final del parser, después de que todas las variables estén asignadas.

### Campos llegan como strings numéricos y no como integers
**Causa:** JSON de Bindplane serializa todos los valores como strings.
**Solución:** Usar `convert => { "campo" => "integer" }` antes de hacer `rename` a campos UDM numéricos.
