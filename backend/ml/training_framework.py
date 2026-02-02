# backend/ml/training_framework.py

from sklearn.model_selection import (
    train_test_split,
    StratifiedKFold,
    cross_val_score
)


class TrainingFramework:
    def __init__(
        self,
        model,
        feature_columns,
        label_column,
        test_size=0.2,
        random_state=42
    ):
        """
        Generic training framework for PhantomNet ML models
        """
        self.model = model
        self.feature_columns = feature_columns
        self.label_column = label_column
        self.test_size = test_size
        self.random_state = random_state

    def prepare_data(self, df):
        """
        Split dataset into train and test sets
        """
        X = df[self.feature_columns]
        y = df[self.label_column]

        return train_test_split(
            X,
            y,
            test_size=self.test_size,
            random_state=self.random_state,
            stratify=y
        )

    def train(self, df):
        """
        Train model and return predictions
        """
        X_train, X_test, y_train, y_test = self.prepare_data(df)

        self.model.fit(X_train, y_train)

        y_pred = self.model.predict(X_test)

        return {
            "model": self.model,
            "X_test": X_test,
            "y_test": y_test,
            "y_pred": y_pred
        }

    def cross_validate(self, df, cv_folds=5, scoring="f1"):
        """
        Perform stratified cross-validation
        """
        X = df[self.feature_columns]
        y = df[self.label_column]

        skf = StratifiedKFold(
            n_splits=cv_folds,
            shuffle=True,
            random_state=self.random_state
        )

        scores = cross_val_score(
            self.model,
            X,
            y,
            cv=skf,
            scoring=scoring
        )

        return {
            "cv_scores": scores,
            "mean_score": scores.mean(),
            "std_score": scores.std()
        }
