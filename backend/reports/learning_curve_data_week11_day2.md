# Learning Curve Analysis (Week 11 Day 2)

## Data Points
| Training Size | Train Accuracy | Validation Accuracy |
|---------------|----------------|---------------------|
| 400 | 1.0000 | 1.0000 |
| 1300 | 1.0000 | 1.0000 |
| 2200 | 1.0000 | 1.0000 |
| 3100 | 1.0000 | 1.0000 |
| 4000 | 1.0000 | 1.0000 |

## Analysis
- **Convergence**: If Train and Validation accuracy converge high, the model is well-fit.
- **Data Requirement**: If the validation score is still rising at the maximum training size, more data could be beneficial.
- **Overfitting**: High gap between train and validation scores indicates overfitting.

## Observations
In our current evaluation with behavioral features, the model achieves high accuracy very quickly, suggesting strong feature signal.
