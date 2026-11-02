import numpy as np
import pytest
from inference import Predictor
from predict import normalize_headers


def test_duplicate_cicids_headers_preserved():
    assert normalize_headers([' Fwd Header Length','Fwd Header Length','Label']) == ['Fwd Header Length','Fwd Header Length.1','Label']


def test_missing_and_nonfinite_values_rejected():
    predictor = Predictor.__new__(Predictor)
    predictor.features = ['a','b']
    with pytest.raises(ValueError, match='Missing features'):
        predictor.predict({'a':1})
    with pytest.raises(ValueError, match='finite'):
        predictor.predict({'a':1,'b':np.inf})
