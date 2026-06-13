
'''A satellite imaging array captures a 10x10 grid of regional ground radiation 
intensities. Analysts require a localized sub-region (bounding box) to be isolated 
for localized anomaly tracking. Any pixel within this specific high-exposure zone 
exceeding a strict critical threshold must be clamped to a maximum safety marker, 
without modifying any surrounding spatial data outside the bounding box.

TECHNICAL APPROACH (LOOP-FREE VECTORIZATION):
1. Grid Simulation: Initialize a 10x10 matrix representing normalized radiation 
   densities using a continuous uniform distribution bounded between 0.0 and 1.0.
2. Matrix Slicing: Extract a direct spatial "view" of the sub-grid by targeting 
   rows 2-6 and columns 2-6 using Python's slice syntax [2:7, 2:7].
3. Conditional Masking: Evaluate a vectorized boolean condition (< threshold) 
   strictly bounded within the scope of the sliced memory view.
4. In-Place Mutation: Directly alter the underlying values of the original 
   matrix using the filtered view, exploiting NumPy's memory optimization rules 
   to completely bypass temporary data copying or loops.'''


import numpy as np

sat1= np.random.uniform(0.0,1.0, size=(10,10)) #initial grid
#now slicing an innerwindow
sat2=sat1[3:7,3:7] #uppper bound exclusive!
#need to find elements >0.7(high intensity) and set them as 1.0 marker
sat2[sat2>0.7]= 1.0
#check if modificstion has taken place
print("Moified 10x10 satellite grid:")
print(np.round(sat1,2))

