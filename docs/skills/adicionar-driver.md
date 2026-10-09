# skill: adicionar driver de vendor

Um driver = parser de configuração de um fabricante. Exemplos reais: `drivers/cisco.py`,
`drivers/juniper.py`. São **4 pontos de registro** — esquecer um deles quebra silenciosamente.

1. **Criar `drivers/<vendor>.py`** herdando `NetworkDriver` (`drivers/base.py`):

```python
from drivers.base import NetworkDriver

class FoobarDriver(NetworkDriver):
    display_name = "Foobar"
    vendor_key = "foobar"
    supports_ssh_extract = True
    supports_bc_extract = True

    def get_ssh_command_setup(self) -> str:   # desativa paginação
        return "terminal length 0"
    def get_config_command(self) -> str:      # dump da config
        return "show running-config"
    def parse_vlans(self, config_text: str) -> list:
        # retorna [{"id": 100, "name": "VLAN_100", "description": "..."}]
        ...
    def parse_subnets(self, config_text: str) -> list:
        ...
    # opcional: parse_device_info(config_text) -> {"model":..., "serial_number":...}
```

2. **Registrar em `back/network_logic.py` → `get_driver_class()`** (~linha 231): adicionar
   `elif vendor == "foobar":` na cadeia, com import dentro de try/ImportError (padrão dos demais).
   Vendor não registrado cai no DummyDriver (não quebra, mas não parseia nada).
3. **Registrar em `back/main.py` → `_CONCRETE_DRIVERS`** (linha ~43): senão o driver não
   aparece no `GET /api/drivers` (frontend não o lista).
4. **Auto-detecção em `back/auto_discovery.py` → `identify_vendor()`** (~linha 162): adicionar
   assinatura textual da config que identifica o vendor. Se o vendor tiver formato próprio de
   IP/porta de gerência, ver `extract_connection_info()` no mesmo arquivo.
5. **Testes**: criar `back/tests/test_drivers_<vendor>.py` no molde de
   `test_drivers_juniper.py` (fixtures com config real anonimizada; cobre parse_vlans,
   parse_subnets, parse_device_info e os comandos SSH).
6. Rodar a suíte (comando em README.md) e conferir `GET /api/drivers` no retorno.
