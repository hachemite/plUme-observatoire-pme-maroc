# ADR 0004: Détection d'Anomalies de Volume par Z-Score Roulant

## Statut
Accepté (Jalon Alt 4)

## Contexte
Le flux de télémétrie CTI présente une saisonnalité et des fluctuations hebdomadaires naturelles. L'utilisation de seuils d'alerte fixes (ex: "alerte si volume > 4000") s'avère inefficace car elle génère des faux positifs lors des pics normaux et ne détecte pas les anomalies relatives survenant en période de creux.

## Décision
Nous implémentons un algorithme de **Z-score roulant (*rolling Z-score*)** avec une fenêtre glissante $W = 3$ semaines :

$$\mu_t = \frac{1}{W}\sum_{i=1}^{W} v_{t-i}, \quad \sigma_t = \sqrt{\frac{1}{W}\sum_{i=1}^{W}(v_{t-i} - \mu_t)^2}$$

$$Z_t = \frac{v_t - \mu_t}{\sigma_t + \epsilon}$$

Une anomalie est signalée lorsque $|Z_t| \ge 2.0$ (écart statistiquement significatif à 95% de confiance).

## Conséquences
- **Avantages** : Adaptabilité automatique aux changements de tendance globale, zéro dépendance à des hyperparamètres rigides.
- **Limites** : Nécessite au moins $W$ points historiques pour amorcer la moyenne et l'écart-type ; une constante de lissage $\epsilon = 10^{-6}$ est ajoutée pour éviter les divisions par zéro.
