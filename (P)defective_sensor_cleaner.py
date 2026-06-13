
'''PROBLEM STATEMENT:
A climate monitoring station records hourly environmental data across multiple 
sensors. Intermittent hardware malfunctions introduce extreme garbage values 
(-999.0, 999.0, or absolute 0.0) into the log matrix. To protect the integrity 
of downstream analytical models, rows containing these sensor anomalies must be 
identified and entirely removed from memory.

TECHNICAL APPROACH (LOOP-FREE VECTORIZATION):
1. Array Structure: Allocate a 1000x3 matrix simulating chronological readings 
   for [Temperature, Pressure, Wind Speed] using a normal (Gaussian) distribution.
2. Multi-Condition Masking: Combine element-wise comparison operators using the 
   bitwise OR (|) operator to construct a 2D boolean grid mapping all corrupted cells.
3. Dimensional Reduction: Collapse the 2D mask into a 1D row filter using 
   .any(axis=1) to target any record suffering from partial sensor failure.
4. Data Extraction: Utilize the bitwise negation operator (~) to slice pristine 
   records out and compute clean global column means via .mean(axis=0).'''


import numpy as np

np.random.seed(42)
data=np.random.normal(loc=25.0,scale=5.0,size=(1000,3))  #temp,pressure,wind speed
#add noise
data[15,0] =-999.0 #frozen temp
data[28,1] =999.0 #extreme pressure
data[68,2] =0.0 #no wind

print(f"Initial data before cleaning :{data.shape}")

pos_dev=(data==999.0)
neg_dev=(data==-999.0)
deadv=(data==0)
filter1=pos_dev|neg_dev|deadv
filterrows=filter1.any(axis=1)    #we had a 1000*3 matrix earlier this is to filter a row if any column hits true and get 1000*1 matrix

cleandata= data[~filterrows]  #gives all tha is left after filtering
cleanavg= cleandata.mean(axis=0) #vertical average

print(f"Cleaned matrix shape:{cleandata.shape}")
print(f"Healthy averages for [Temperatur, pressure, wind]: {cleanavg}")
