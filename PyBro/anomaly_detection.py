"""비정상 탐지 프로그램"""
"""Reference : https://github.com/Kitware/bat/blob/master/examples/anomaly_detection.py"""
from __future__ import print_function
import os
import sys
import argparse
import math
from collections import Counter

# 사용할 모듈
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.cluster import KMeans
from bat import log_to_dataframe
from bat import dataframe_to_matrix

# 메인 함수
if __name__ == '__main__':
    # pandas 내 dataframe 보여줄 때 너비 1000으로 해서 고정
    pd.set_option('display.width', 1000)

    # argument 수집
    parser = argparse.ArgumentParser()
    parser.add_argument('bro_log', type=str, help='Specify a bro log to run BroLogReader test on')
    args, commands = parser.parse_known_args()

    # arguments 확인
    if commands:
        print('Unrecognized args: %s' % commands)
        sys.exit(1)

    # Bro log 파일 열기
    if args.bro_log:
        args.bro_log = os.path.expanduser(args.bro_log)

        # http.log 파일이면 특징값 뽑아내고, 아니면 오류 메시지 출력하면서 종료
        if 'http' in args.bro_log:
            log_type = 'http'
            features = ['id.resp_p', 'method', 'resp_mime_types', 'request_body_len']
        else:
            print('This example only works with Bro with http.log or dns.log files..')
            sys.exit(1)

        # Bro log 파일을 데이터 프레임화
        try:
            bro_df = log_to_dataframe.LogToDataFrame(args.bro_log)
        except IOError:
            print('Could not open or parse the specified logfile: %s' % args.bro_log)
            sys.exit(1)
        print('Read in {:d} Rows...'.format(len(bro_df)))

        # bat 모듈을 사용해서 Dataframe -> Matrix 변형
        to_matrix = dataframe_to_matrix.DataFrameToMatrix()
        bro_matrix = to_matrix.fit_transform(bro_df[features])
        print(bro_matrix.shape)

        # IsolationForest라는 이상탐지 알고리즘 사용
        # contamination = 데이터 셋에 대한 이상치의 비율
        odd_clf = IsolationForest(contamination=0.2) 
        odd_clf.fit(bro_matrix)

        #  Dataframe 으로 만들기
        odd_df = bro_df[features][odd_clf.predict(bro_matrix) == -1]

        # K 평균 알고리즘으로 군집화
        odd_matrix = to_matrix.fit_transform(odd_df)
        num_clusters = min(len(odd_df), 4) # 4 clusters unless we have less than 4 observations
        odd_df['cluster'] = KMeans(n_clusters=num_clusters).fit_predict(odd_matrix)
        print(odd_matrix.shape)

        # 데이터 프레임으로 구성된 군집 생성
        cluster_groups = odd_df[features+['cluster']].groupby('cluster')

        # 위의 생성된 데이터 프레임 군집 출력
        print('<<< Outliers Detected! >>>')
        for key, group in cluster_groups:
            print('\nCluster {:d}: {:d} observations'.format(key, len(group)))
            print(group.head())
