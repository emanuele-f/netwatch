
function dateZeroHour(dt) {
  dt.setHours(0, 0, 0, 0);
  return dt;
}

function dateTolocaldate(ev_dt) {
  var dt = new Date(ev_dt);
  var ts_local = dt.getTime() + new Date().getTimezoneOffset() * 60 * 1000;
  return new Date(ts_local);
}

function makeDateTimePicker(picker_id, timestamp, resolution) {
  var selector = "#" + picker_id;
  var form = $(selector).closest("form");
  var changing_minute = false;
  var dt_input = $(selector).find("input");

  var submitTimeframe = function(dt, res) {
    var ts_input = form.find("input[name='ts']");
    var res_input = form.find("input[name='res']");
    var ts = dt.getTime() / 1000;

    ts_input.val(ts);
    res_input.val(res);
    form.submit();
  }

  var res2view = {
    "1m": 0,
    "1h": 1,
    "24h": 2,
    "1M": 3,
  }

  var startView = res2view[resolution];
  var currentDate = new Date(timestamp * 1000);
  dt_input.val(moment(currentDate).format("YYYY-MM-DD HH:mm"));

  var picker = $(selector).datetimepicker({
    fontAwesome: true,
    minuteStep: 15,
    todayBtn: true,
    endDate: new Date(),
    startView: startView,
  }).on('changeYear', function(ev) {
    var dt = dateTolocaldate(ev.date.valueOf());

    dateZeroHour(dt);
    dt.setMonth(0, 1);
    submitTimeframe(dt, "1M");
  }).on('changeMonth', function(ev) {
    var dt = dateTolocaldate(ev.date.valueOf());

    dateZeroHour(dt);
    dt.setMonth(dt.getMonth(), 1);
    submitTimeframe(dt, "24h");
  }).on('changeDay', function(ev) {
    var dt = dateTolocaldate(ev.date.valueOf());

    submitTimeframe(dateZeroHour(dt), "1h");
  }).on('changeHour', function(ev) {
    var dt = dateTolocaldate(ev.date.valueOf());

    dt.setMinutes(0);
    dt.setSeconds(0);
    dt.setMilliseconds(0);
    submitTimeframe(dt, "1m");
  }).on('changeMinute', function(ev) {
    var dt = dateTolocaldate(ev.date.valueOf());
    changing_minute = true;

    dt.setSeconds(0);
    dt.setMilliseconds(0);
    submitTimeframe(dt, "1m");
  }).on('changeDate', function(ev) {
    // TODO
    if (! changing_minute)
      console.log("Now ", ev.date.valueOf());
  });

  return picker;
}

$.fn.datetimepicker.dates['en'] = $.extend($.fn.datetimepicker.dates['en'], {
  today: "Now",
});
