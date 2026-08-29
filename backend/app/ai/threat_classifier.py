import torch
import torch.nn as nn
import torch.nn.functional as F

VOCABULARY = [
    "mimikatz", "lsass", "sam", "shadow", "system32", "secretdump", # Credential Access
    "netcat", "nc.exe", "reverse", "shell", "curl", "wget", "port", # Command & Control
    "exfiltrate", "mega.nz", "sftp", "upload", "ftp", "dropbox", # Data Exfiltration
    "taskkill", "firewall", "bypass", "defender", "reg add", "hidden", # Defense Evasion
    "runas", "privilege", "sudo", "whoami", "uac", "administrator" # Privilege Escalation
]

CATEGORIES = [
    "Credential Access",
    "Command & Control",
    "Data Exfiltration",
    "Defense Evasion",
    "Privilege Escalation",
    "Clean / General"
]

RECOMMENDATIONS = {
    "Credential Access": "Change passwords immediately, revoke active tokens, and check for golden ticket Kerberos attacks.",
    "Command & Control": "Block the associated IP endpoints at the firewall, inspect active TCP connections, and isolate the endpoint.",
    "Data Exfiltration": "Audit DNS queries, check cloud upload logs, and verify file transfer connections.",
    "Defense Evasion": "Restore antivirus policies, check registry audit trails, and review system configuration changes.",
    "Privilege Escalation": "Audit administrator group memberships, check local user creation events, and inspect active processes.",
    "Clean / General": "No immediate remediation required. Standard verification checks passed."
}

class ForensicClassificationNet(nn.Module):
    """PyTorch MLP classifier mapping TF-IDF bag-of-words forensic signals to MITRE categories."""
    def __init__(self, vocab_size, num_classes):
        super().__init__()
        self.fc1 = nn.Linear(vocab_size, 16)
        self.fc2 = nn.Linear(16, num_classes)

    def forward(self, x):
        x = F.relu(self.fc1(x))
        x = self.fc2(x)
        return x

class ThreatClassifier:
    def __init__(self):
        self.vocab = VOCABULARY
        self.categories = CATEGORIES
        self.model = ForensicClassificationNet(len(self.vocab), len(self.categories))
        self.model.eval()
        self._init_weights()

    def _init_weights(self):
        """Pre-populate network weights to activate on specific bag-of-words keywords."""
        with torch.no_grad():
            # Zero out weights
            self.model.fc1.weight.zero_()
            self.model.fc1.bias.zero_()
            self.model.fc2.weight.zero_()
            self.model.fc2.bias.zero_()
            
            # Map vocab indices to hidden nodes, then map to categories
            # Vocabulary is grouped in blocks of 6 words per category
            for i in range(5): # 5 threat categories
                for offset in range(6):
                    vocab_idx = i * 6 + offset
                    hidden_node = i
                    # Let the vocab index activate hidden node i
                    self.model.fc1.weight[hidden_node, vocab_idx] = 1.5
                    # Let hidden node i activate class category i
                    self.model.fc2.weight[i, hidden_node] = 2.0
            
            # Category 5 is Clean/General. We can set a small positive bias to default to clean
            self.model.fc2.bias[5] = 0.5

    def text_to_tensor(self, text: str) -> torch.Tensor:
        """Create a bag-of-words float tensor matching vocabulary terms."""
        text_lower = text.lower()
        vector = [1.0 if term in text_lower else 0.0 for term in self.vocab]
        return torch.tensor([vector], dtype=torch.float32)

    def classify_text(self, text: str) -> dict:
        """Classify inputs through forward propagation returning class, confidence, and reasons."""
        x = self.text_to_tensor(text)
        with torch.no_grad():
            outputs = self.model(x)
            probabilities = F.softmax(outputs, dim=1)[0]
            max_prob, max_idx_tensor = torch.max(probabilities, dim=0)
            
            confidence = float(max_prob)
            class_idx = int(max_idx_tensor)
            category = self.categories[class_idx]
            
        reason = f"PyTorch neural classifier detected keyword alignment for '{category}' with a forward propagation score of {confidence:.3f}."
        if category == "Clean / General":
            reason = "No high-signal malicious forensic keywords matches were detected by the PyTorch classification network."

        return {
            "threat_category": category,
            "confidence": confidence,
            "reason": reason,
            "recommendation": RECOMMENDATIONS[category]
        }
