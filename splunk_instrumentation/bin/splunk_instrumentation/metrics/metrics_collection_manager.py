import json
from datetime import datetime

from metrics_transforms import transform_object
from splunk_instrumentation.constants import INST_EXECUTION_ID
from splunk_instrumentation.datetime_util import date_to_timestamp, utcNow, str_to_date
from splunk_instrumentation.report import report
from splunk_instrumentation.metrics.instance_profile import get_instance_profile, evaluate_roles


class MetricsCollectionManager:
    def __init__(self, metricSchema, dataPointFactory, splunkrc=None):
        self.metricSchema = metricSchema
        self.dataPointFactory = dataPointFactory
        self.splunkrc = splunkrc
        self.profile = get_instance_profile()

    def collect_data(self, dateRange, on_send=False, callback=None):
        '''
        loads all data classes from schema and collects data for yesterday.
        callback will be run after it collects data
        '''
        self._collect_classes_data(dateRange, on_send, callback)

    def collect_data_date_range(self, start, stop, on_send=False, callback=None):
        dateRange = {"start": start, "stop": stop}
        self._collect_classes_data(dateRange, on_send, callback)

    def _collect_classes_data(self, dateRange, on_send, callback=None):
        classes = self.metricSchema.getEventClassByfield(on_send, "on_send", False)
        for classDef in classes:
            rules = classDef.getRoles()
            if evaluate_roles(self.profile.roles, rules):
                self._collect_class_data(classDef, dateRange, callback)

    def _collect_class_data(self, classDef, dateRange, callback=None):
        '''
        run data collections and call callbacks on it.
        '''
        try:
            if not isinstance(dateRange, dict):
                dateRange = {"start": dateRange}
            dateRange["stop"] = dateRange.get("stop") or dateRange.get("start")

            if isinstance(dateRange["start"], datetime) or isinstance(dateRange["stop"], datetime):
                raise "Requires_date_not_datetime"

            dataPoints = classDef.getDataPoints()

            for dataPoint in dataPoints:
                report.start_profiling()
                dataPointResult = self.collect_data_point(dataPoint, dateRange)

                if hasattr(dataPointResult, 'job'):
                    try:
                        report.report('components[]', {
                            "component": classDef.component,
                            "runDuration": float(dataPointResult.job["runDuration"]),
                            "scanCount": int(dataPointResult.job["scanCount"]),
                            "resultCount": int(dataPointResult.job["resultCount"]),
                            "isFailed": dataPointResult.job["isFailed"],
                            "searchProviders": len(dataPointResult.job["searchProviders"]),
                            "sid": dataPointResult.job["sid"]

                        })
                    except:
                        report.report('components[]', {
                            "component": classDef.component,
                            "error": "could not log report"
                            })

                dataPointResult = [
                    self.data_point_results_transform(classDef, event, dateRange) for event in dataPointResult]

                callback(dataPointResult)

        except Exception as e:
            report.report('exceptions[]', str(e))

    def collect_data_point(self, dataPoint, dateRange):
        dataPointObj = self.dataPointFactory(dataPoint, options={"splunkrc": self.splunkrc})
        data = dataPointObj.collect(dateRange)
        return data

    def data_point_results_transform(self, class_def, data_point_result, date_range):
        fields = class_def.index_fields

        result = {"data": None}
        if data_point_result['data']:
            if (isinstance(data_point_result['data'], basestring)):
                data = json.loads(data_point_result['data'])
            else:
                data = data_point_result['data']
            data = transform_object(data=data, fields=fields)
            result['data'] = data
        result['timestamp'] = date_to_timestamp(utcNow())

        result['component'] = class_def.component
        result['date'] = date_range['stop'].isoformat()

        data_point_time = data_point_result.get('_time')

        if not date_range['stop'] == date_range['start']:
            try:
                if data_point_result.get('date'):
                    result['date'] = data_point_result.get('date')
                elif data_point_time and 'T' in data_point_time:
                    result['date'] = data_point_result.get('_time').split('T')[0]
            except Exception:
                result['date'] = date_range['stop'].isoformat()

        # SPECIAL CASE:
        # At least one (the indexer cluster member count) data point is retrieved
        # on the fly during data collection. Its time/date will be "today" though
        # it really pertains to the stop date (typically yesterday in prod).
        # Note - There is discussion of having each node persist this data so the
        #        true historical values can be retrieved later. That would eliminate
        #        this situation.
        if str_to_date(result['date']) > date_range['stop']:
            result['date'] = date_range['stop']

        result['visibility'] = class_def.visibility or "anonymous"
        result['executionID'] = INST_EXECUTION_ID

        return result
