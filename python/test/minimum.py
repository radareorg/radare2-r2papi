import r2pipe
import r2api

api = r2api.R2Api("/bin/ls")
print(api.info().arch)
api.quit()
