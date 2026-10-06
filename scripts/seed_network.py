import sys
import random
sys.path.insert(0, 'backend')
from app.database.session import SessionLocal
from app.models.case import Case
from app.models.evidence import Evidence
from app.models.network_artifact import NetworkArtifact

db = SessionLocal()
cases = db.query(Case).all()

db.query(NetworkArtifact).delete()
db.commit()

def random_internal_ip():
    return f"10.0.{random.randint(1, 10)}.{random.randint(2, 254)}"

def random_external_ip():
    return f"{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}"

count = 0
for case in cases:
    ev = db.query(Evidence).filter(Evidence.case_id == case.id).first()
    if not ev:
        ev = Evidence(case_id=case.id, filename='mock_network.csv', file_size=1024, sha1='0', sha256='0', extension='csv', uploader_id=1, stored_path='mock_network.csv', mimetype='text/csv')
        db.add(ev)
        db.commit()
    
    num_artifacts = random.randint(5, 12)
    
    core_internals = [random_internal_ip() for _ in range(random.randint(1, 2))]
    
    core_externals = [random_external_ip() for _ in range(random.randint(1, 3))]
    
    for _ in range(num_artifacts):
        src = random.choice(core_internals) if random.random() < 0.8 else random_internal_ip()
        dst = random.choice(core_externals) if random.random() < 0.8 else random_external_ip()
        
        protocol = random.choice(['TCP', 'UDP', 'HTTP', 'HTTPS', 'DNS', 'SSH', 'FTP'])
        
        art = NetworkArtifact(
            case_id=case.id,
            evidence_id=ev.id,
            artifact_type='firewall_log',
            source_ip=src,
            destination_ip=dst,
            value=protocol
        )
        db.add(art)
        count += 1

db.commit()
print(f'Cleared old artifacts and added {count} new random network artifacts across {len(cases)} cases.')
