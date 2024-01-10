import r2pipe
import r2papi

api = r2papi.R2Api("/bin/ls")
print(api.info().arch)
api.quit()
