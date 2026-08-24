import yaml
from models import Identity, TestContext

def load_credentials(path: str) -> TestContext:
  with open(path) as f:
    raw = yaml.safe_load(f)
    
  identities = [Identity(**item) for item in raw["identities"]]
  return TestContext(identities=identities) 