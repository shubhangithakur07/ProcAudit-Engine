
'''An oceanographic study deploys 5 marine buoys tracking 4 separate environmental 
metrics over a continuous 100-day timeline. To monitor systemic ecological 
threats, researchers must calculate historical peaks and baseline profiles per 
station. Additionally, they must isolate specific calendar dates where an environmental 
hazard simultaneously crossed a critical limit across all active tracking stations.

TECHNICAL APPROACH (LOOP-FREE VECTORIZATION):
1. Tensor Architecture: Construct a 3D NumPy array of shape (5, 100, 4) mapping 
   [Buoys, Days, Metrics], where metrics represent [Salinity, Temp, pH, Oxygen].
2. Multi-Axis Reduction: Eradicate spatial and temporal variables simultaneously 
   by executing .max(axis=(0,1)) to isolate global absolute metric peaks.
3. Temporal Axis Collapse: Compute individualized, long-term buoy environmental 
   fingerprints by averaging out daily fluctuations using .mean(axis=1).
4. Synchronous Vectorized Intersection: Slice out the 2D pH plane [:, :, 2], 
   apply a boolean threshold check, and collapse rows using .all(axis=0) to 
   guarantee strict intersection matching. Track coordinates via np.where()[0]'''


import numpy as np
tensor=np.random.uniform(low=0.0,high=14.0,size=(5,100,4))
#0-salinity,1-temperature,2-ph,3-dissolved oxygen
mxm=tensor.max(axis=(0,1)) #max across all buoys across 100 days
#only axis 2 left so result shape=(4,)
print(f"Max values for the 4 metrics: {mxm}")
avgc=tensor.mean(axis=1)  #result shape=(5,4)
print(f"Average profile for Buoy 0: {avgc[0]}")

phdata=tensor[:,:,2]
critical=phdata<6.0  #gives boolean matrix
criticaldays=np.where(critical.all(axis=0))[0]
print(f"Days where ALL stations dropped below critical pH: {criticaldays}")