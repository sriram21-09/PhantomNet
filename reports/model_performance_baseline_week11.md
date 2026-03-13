# Model Performance Baseline (Week 11)

## Metrics
- **Model Size**: 0.38 MB
- **Single Inference Latency**: 100.09 ms
- **Batch Latency (1000 samples)**: 148.49 ms
- **Number of Features expected**: 12

## Profiling (Top Operations)
```text
         115644620 function calls (114200397 primitive calls) in 124.790 seconds

   Ordered by: cumulative time
   List reduced from 414 to 15 due to restriction <15>

   ncalls  tottime  percall  cumtime  percall filename:lineno(function)
   251000    0.445    0.000  240.522    0.001 C:\Users\shalo\AppData\Local\Programs\Python\Python314\Lib\site-packages\joblib\parallel.py:1670(_get_outputs)
      972    0.041    0.000  214.836    0.221 C:\Users\shalo\AppData\Local\Programs\Python\Python314\Lib\multiprocessing\pool.py:500(_wait_for_updates)
     1500    0.007    0.000  130.688    0.087 C:\Users\shalo\AppData\Local\Programs\Python\Python314\Lib\threading.py:1096(join)
     1500    0.793    0.001  130.678    0.087 {method 'join' of '_thread._ThreadHandle' objects}
      500    0.007    0.000  126.255    0.253 C:\Users\shalo\AppData\Local\Programs\Python\Python314\Lib\site-packages\sklearn\ensemble\_forest.py:882(predict)
      500    0.037    0.000  126.237    0.252 C:\Users\shalo\AppData\Local\Programs\Python\Python314\Lib\site-packages\sklearn\ensemble\_forest.py:921(predict_proba)
      500    0.004    0.000  125.196    0.250 C:\Users\shalo\AppData\Local\Programs\Python\Python314\Lib\site-packages\sklearn\utils\parallel.py:54(__call__)
      500    0.023    0.000  125.188    0.250 C:\Users\shalo\AppData\Local\Programs\Python\Python314\Lib\site-packages\joblib\parallel.py:1969(__call__)
      500    0.002    0.000  125.057    0.250 C:\Users\shalo\AppData\Local\Programs\Python\Python314\Lib\site-packages\joblib\parallel.py:1403(_terminate_and_reset)
      500    0.045    0.000  125.055    0.250 C:\Users\shalo\AppData\Local\Programs\Python\Python314\Lib\site-packages\joblib\_parallel_backends.py:323(terminate)
      500    0.029    0.000  124.728    0.249 C:\Users\shalo\AppData\Local\Programs\Python\Python314\Lib\multiprocessing\pool.py:654(terminate)
      500    0.006    0.000  124.452    0.249 C:\Users\shalo\AppData\Local\Programs\Python\Python314\Lib\multiprocessing\util.py:272(__call__)
      500    0.007    0.000  124.443    0.249 C:\Users\shalo\AppData\Local\Programs\Python\Python314\Lib\multiprocessing\pool.py:680(_terminate_pool)
 7500/500    0.331    0.000  123.254    0.247 C:\Users\shalo\AppData\Local\Programs\Python\Python314\Lib\threading.py:1029(_bootstrap)
 7500/500    0.234    0.000  122.753    0.246 C:\Users\shalo\AppData\Local\Programs\Python\Python314\Lib\threading.py:1064(_bootstrap_inner)



```
