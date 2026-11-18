# Autenticación de sportsbook

Worker Hono con dos rutas bajo el origen del frontend. `GET /at-auth/v1/health` devuelve el estado local. `POST /at-auth/v1/auth/anonymous` solicita o reutiliza un JWT de FIRST y devuelve `201` con `data.token`. Las respuestas incluyen `Cache-Control: no-store` y un identificador de correlación.

## Desarrollo local

Con Node.js 24, ejecutar `npm ci`, copiar `.dev.vars.example` a `.dev.vars` y completar la configuración de FIRST de pruebas. Usar un secreto de sesión independiente, aleatorio y de al menos 32 bytes. Iniciar con `npm run dev`. Ejecutar `npm test` para probar el Worker en Miniflare con FIRST simulado. `npm run build` valida el empaquetado con Wrangler.

## Configuración por ambiente

`FIRST_API_VERSION=v1` selecciona el GET con `configurationJWT` que usa `msa-digital-auth`. El valor `v2` (predeterminado) selecciona el POST con `signedRequest`. La ruta pública del Worker recibe POST en ambos casos.

Usar un Worker y un namespace de Durable Objects propios de cada ambiente. Definir `APP_ENV`, la URL HTTPS de FIRST, el agente, el dominio y los tiempos del adaptador. Configurar `FIRST_CONFIGURATION_JWT_SECRET` y `SESSION_COOKIE_SECRET` como secretos de Workers. Rotar el segundo invalida las cookies existentes. Para el despliegue, asignar las dos rutas al host del frontend y definir ambos bindings de rate limiting en la configuración del ambiente, con namespace IDs propios. Los límites locales de 30 solicitudes por sesión y 120 por IP cada 60 segundos son valores de prueba. Calibrarlos antes de producción.

El cliente conserva la cookie de sesión firmada, opaca, `HttpOnly` y `Secure`. Las solicitudes iniciales concurrentes sin cookie pueden crear sesiones distintas. La caché se aísla por ambiente, agente, dominio y sesión. Si quedan cinco minutos o menos, la siguiente consulta renueva el token. Se consulta FIRST directamente ante una caída del Durable Object. Un error de FIRST se comunica al cliente sin una segunda emisión automática. Los límites se aplican antes de consultar el objeto o FIRST.
