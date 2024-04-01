from sklearn.metrics import classification_report, confusion_matrix
import seaborn as sn
import pandas as pd
import matplotlib.pyplot as plt

# This utility function will be used to evaluate the other models also.
def show_performance_data(Y_test, Y_pred, model_name):
  print(classification_report(Y_test, Y_pred, target_names=labels))
  tmp_result = classification_report(Y_test, Y_pred, target_names=labels, output_dict=True)
  cm1 = confusion_matrix(Y_test, Y_pred)
  df_cm = pd.DataFrame(cm1, index = [i for i in labels], columns = [i for i in labels])
  plt.figure(figsize = (7,5))
  sn.heatmap(df_cm, annot=True,cmap='gist_earth_r', fmt='g')
  plt.savefig('confusion_mrtx_'+model_name+'.png',bbox_inches = 'tight')
  return tmp_result

result_word2vec = show_performance_data(Y_test, Y_pred, 'word2vec')