import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

class IsolationForestModel:
    def __init__(self):
        self.model   = IsolationForest(
            contamination=0.05,
            random_state=42,
            n_estimators=100
        )
        self.scaler  = StandardScaler()
        self.buffer  = []
        self.trained = False

    def update(self, vector):
        self.buffer.append(vector)
        if len(self.buffer) < 50:
            return False, 0.0
        if not self.trained or len(self.buffer) % 20 == 0:
            X = self.scaler.fit_transform(np.array(self.buffer))
            self.model.fit(X)
            self.trained = True
        X_new = self.scaler.transform([vector])
        score = self.model.score_samples(X_new)[0]
        is_anomaly = self.model.predict(X_new)[0] == -1
        return is_anomaly, float(score)