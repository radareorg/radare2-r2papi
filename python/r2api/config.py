from .base import R2Base, ResultArray


class ConfigType(R2Base):

    def __init__(self, r2, var_type):
        super(ConfigType, self).__init__(r2)

        valid_vars = []
        for v in self._exec("e??j %s" % var_type, json=True):
            valid_vars.append(v["name"].split(".")[1])

            # Update directly from __dict__ to avoid __setattr__ and
            # __getattr__
        self.__dict__["valid_vars"] = valid_vars
        self.__dict__["var_type"] = var_type

    def __getattr__(self, attr):
        if attr in self.valid_vars:
            ret = self._exec("e %s.%s" % (self.var_type, attr))
            if ret.isdigit():
                ret = int(ret)
            elif ret == "true":
                ret = True
            elif ret == "false":
                ret = False
            return ret
        else:
            raise AttributeError()

    def __setattr__(self, attr, val):
        # Dirty way to avoid infinite recursion
        if attr == "r2" or attr == "_tmp_off":
            self.__dict__[attr] = val
        elif attr in self.valid_vars:
            if attr == True:
                attr = "true"
            if attr == False:
                attr = "false"
            self._exec("e %s.%s = %s" % (self.var_type, attr, val))
        else:
            raise AttributeError()


class Config(R2Base):

    def __init__(self, r2):
        super(Config, self).__init__(r2)

        # anal, scr, asm, io...
        self.vars_types = []
        v = self._exec("e??j", json=True)
        for var in v:
            var_type = var["name"].split(".")[0]
            if var_type not in self.vars_types:
                self.vars_types.append(var_type)

    def __getattr__(self, attr):
        if attr in self.vars_types:
            return ConfigType(self.r2, attr)
