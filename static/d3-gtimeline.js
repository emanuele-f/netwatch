(function (global, factory) {
	typeof exports === 'object' && typeof module !== 'undefined' ? factory(exports, require('moment/moment')) :
	typeof define === 'function' && define.amd ? define(['exports', 'moment/moment'], factory) :
	(factory((global.d3 = global.d3 || {}),global.moment));
}(this, (function (exports,moment) { 'use strict';

moment = 'default' in moment ? moment['default'] : moment;

var css = 'div.tooltip {\
        position: absolute;\
        text-align: center;\
        padding: 5px;\
        /* font: 12px sans-serif; */\
        background: white;\
        border: 1px solid #AAA;\
        border-radius: 2px;\
        pointer-events: none;\
      }';

var tooltip = function (html_func) {

    d3.select('head')
        .selectAll('#tooltip').data([1]).enter()
            .append('style')
            .attr('id', 'tooltip')
            .text(css);

    var selection = d3.select("body").append("div")
        .attr("class", "tooltip")
        .style("opacity", 0);
  
    selection.show = function(){
        selection.transition()
            .duration(100)
            .style("opacity", .95);
        selection.html(html_func.apply(null, arguments))
            .style("left", (d3.event.pageX) + "px")
            .style("top", (d3.event.pageY - 28) + "px");
    };

    selection.hide = function(d){
        selection.transition()
            .duration(100)
            .style("opacity", 0);
    };

    return selection;
};

function identity(x) {
    return x;
}

var right = 1;
var left = 2;

function timelineAxis(orient, scale) {
    var colors = ['#FFF','#EEE'],
        padding = 5,
        range,
        line_color = '#AAA',
        trim = 40,
        width = 100;

    function max_text_width(selection) {
        return d3.max(selection.nodes().map(d => d.getComputedTextLength()));
    }

    function trim_long_string(value) {
        return function(d){
            return d.length > value? d.slice(0, value-1)+'\u2026': d
        }
    }

    function axis(selection) {
        var domain = scale.domain(),
            tip = tooltip(identity),
            colorscale = d3.scaleOrdinal(colors),
            invertscale = d3.scaleOrdinal(colors.reverse()),
            labels = trim_long_string(trim),
            row = selection.selectAll('.row').data(domain, scale).order(),
            rowEnter = row.enter().append('g').attr('class', 'row'),
            rowExit = row.exit(),
            texts = row.select('text');

        row = row.merge(rowEnter)
            .attr("transform", (d)=>"translate(0," + scale(d) + ")");

        rowExit.remove();

        rowEnter.append('rect')
            .attr('y', 0.5)
            .attr('width', width)
            .attr('height', scale.bandwidth())
            .attr('stroke', line_color)
            .attr('stroke-width', 0.75)
            .attr('fill', colorscale);  // should be re-done if domain changed?

        rowEnter.append('path')
            .attr('stroke', invertscale);

        texts = texts.merge(rowEnter.append('text')
            .attr('y', scale.bandwidth()/2)
            .attr('dy', "0.32em")
            .on('mouseover', function(d) {
                if(d3.select(this).text() != d)
                    tip.show(d);
            })
            .on('mouseout', tip.hide))
        .text(labels);

        var offset = max_text_width(texts) + 2*padding;
        offset = orient === right ? width - offset: offset;

        range = orient === right ? [0, offset]: [offset, width];

        texts
            .attr("text-anchor", orient === right ? "start" : "end")
            .attr('dx', orient === right ? padding: -padding)
            .attr('x', offset);

        selection.append('path')
            .attr('stroke',  line_color)
            .attr('d','M'+(offset+.5)+',0.5V'+scale.range()[1]);
    }

    axis.draw_ticks = function(selection, ticks) { 
        selection.selectAll('.row').select('path')
            .attr('d', ticks.map((t)=> 'M'+t+','+1+'v'+(scale.bandwidth()-1)).join(''));
    };

    axis.scale   = function(_) { return arguments.length? (scale   = _, axis): scale };
    axis.width   = function(_) { return arguments.length? (width   = _, axis): width };
    axis.colors  = function(_) { return arguments.length? (colors  = _, axis): colors };
    axis.padding = function(_) { return arguments.length? (padding = _, axis): padding };
    axis.range   = function(_) { return arguments.length? (range   = _, axis): range };
    axis.trim    = function(_) { return arguments.length? (trim    = _, axis): trim };

    return axis;
}

function timelineAxisLeft(scale) {
  return timelineAxis(left, scale);
}

function timelineAxisRight(scale) {
  return timelineAxis(right, scale);
}

//var moment = require("moment"),
//    d3 = require("d3");
    
//import { createDuration } from 'moment/src/lib/duration/create';
//import {humanize} from 'moment/src/lib/duration/humanize';

function durationFormat(start, end) {
    //return createDuration(end-start).humanize();
	if(moment)
    	return moment.duration(end-start).humanize();
		
    var seconds = d3.timeSecond.count(start,end),
        cut_off = 2;
    if (seconds < cut_off*60)
        return seconds + 's'
    else if (seconds < cut_off*60*60)
        return d3.timeMinute.count(start, end) + ' min'
    else if (seconds < cut_off*60*60*24)
        return d3.timeHour.count(start, end) + ' hours'
    else if (seconds < cut_off * 3600 * 24 * 30)
        return d3.timeDay.count(start, end) + ' day(s)'
    else if (seconds < cut_off * 3600 * 24 * 365)
        return d3.timeMonth.count(start, end) + ' month(s)'
    else 
        return d3.timeYear.count(start, end) + ' year(s)';

}

//
// Function composition
//
Function.prototype.wrap = function(g) {
     var fn = this;
     return function() {
         return g.call(this, fn.apply(this, arguments));
     };
};

Function.prototype.compose = function(g) {
     var fn = this;
     return function() {
         return fn.call(this, g.apply(this, arguments));
     };
};



function f(value) {
    return function(d) {
        return value === undefined? d: d[value];
    }
}

var google_colors = [ 
	"#4285f4", "#db4437", "#f4b400", "#0f9d58", "#ab47bc", "#5e97f5", "#e06055", 
	"#f5bf26", "#33ab71", "#b762c6", "#00acc1", "#ff855f", "#9e9d24", "#26b8ca", "#ff7043"];

function getFontSize(element){
    var style = window.getComputedStyle(element, null).getPropertyValue('font-size');
    return parseFloat(style); 
}

function luma_BT709(c) {
	return (c.r*0.299 + c.g*0.587 + c.b*0.114);
}

function isBright(color) {
    return luma_BT709(color) > 165; // original is 186, but I prefer that value
}

function textColor(value) {
    return isBright(d3.color(value))? 'black': 'white';
}

function translate(x, y) {
    return "translate(" + x + ',' + y + ')';
}

var timeline = function() {
    function tooltip_html(d,i) {
        //var format = (d)=>d3.timeFormat("%Y-%m-%d")(d3.isoParse(d));
        var format = d3.isoParse.wrap(d3.timeFormat("%Y-%m-%d"));
//        var format = compose(d3.isoParse, d3.timeFormat("%Y-%m-%d"));
		return  '<b>'+ names(d) + '</b>' + 
                '<hr style="margin: 2px 0 2px 0">' +
                format(starts(d)) + ' - ' + format(ends(d)) + '<br>' +
                durationFormat(starts(d), ends(d));
    }

    var colors = google_colors,
        padding = 5,
        reversed = false,
        today = false,
        dates,
        const_width,
        duration = 0,
        labels = f(0),
        names  = f(1),
        starts = f(2),
        ends   = f(3),
        tooltip_render = tooltip_html,
        min_width = 0,
        on_item_click = $.noop;

    function trim_text(d, i) {
        var task = d3.select(this.parentNode),
            text = task.select('text'),
            rect = task.select('rect'),
            string = names(d),
            text_width = text.node().getComputedTextLength();  

        // this is overkill if duration is 0
        d3.active(this)
            .tween('text', function () {
                return function(t) {
                    var width = rect.attr('width') - 2*padding,
                        ratio = width / text_width;
                    text.text(ratio < 1? string.substring(0, Math.floor(string.length * ratio)): string);
                }
            });
    }

    function chart(selection) {
        var 
            data = selection.datum(),
            rows = d3.map(data, labels).keys(),
            tip = new tooltip(tooltip_render),
            cScale = d3.scaleOrdinal(colors);

        dates = dates || [d3.min(data, starts), d3.max(data, ends)];

        // Work with single points: give rect some syntetic width
        var half_min_msecs = min_width * 0.5;

        function starts_min_width(d) {
            var start_d = starts(d);
            var end_d = ends(d);
            var rv = ((end_d - start_d) < min_width) ? (new Date(start_d - half_min_msecs)) : start_d;
            //console.log("start", start_d, rv);

            return rv;
        }

        function ends_min_width(d) {
            var start_d = starts(d);
            var end_d = ends(d);
            var rv = ((end_d - start_d) < min_width) ? (new Date(end_d - (- half_min_msecs))) : end_d;
            //console.log("End: ", d[0], end_d, starts_min_width(d), "->", rv);

            return rv;
        }

        selection.each(function(data){
            var width = const_width || this.getBoundingClientRect().width,
                height = rows.length * (getFontSize(this) + 4*padding),
                yScale = d3.scaleBand().domain(rows).range([0, height]), //.padding(0.1),
                xScale = d3.scaleTime().domain(dates),
                yAxis = (reversed? timelineAxisRight: timelineAxisLeft)(yScale).width(width),
                svg = d3.select(this).append('svg').attr('class', 'timeline');

            svg.attr('width', width);
            svg.attr('height', height + 20); // margin.bottom
            
            var g = svg.append('g');

            var yGroup = g.append('g')
                .attr('class', 'y axis')
                .call(yAxis);

            var range = yAxis.range();
            xScale.range([range[0]+padding, range[1]-padding]).clamp(true);
            var xAxis = d3.axisBottom(xScale);
            var xGroup = g.append('g')
                .attr('class', 'x axis')
                .attr("transform", translate(0, height))
                  .call(xAxis);

            xGroup.select('.domain').remove();
            xGroup.selectAll('.tick line').attr('stroke', '#AAA');

            var ticks = xScale.ticks().map(xScale);        
            yGroup.call(yAxis.draw_ticks, ticks);

            var tasks = g.selectAll('g.task').data(data);

            tasks.exit().remove();

            var tasks_enter = tasks.enter()
                .append('g')
                .classed('task', true);

            tasks_enter
                .append('rect')
                .attr('y', padding)
                .attr('height', yScale.bandwidth() - 2*padding)
                .on('mouseover', tip.show)
                .on('mouseout', tip.hide)
                .on("click", on_item_click)
                .style('fill', names.wrap(cScale));

            tasks_enter
                .append('text')
                .attr("text-anchor", "start")
                .attr('fill', d => textColor(cScale(names(d))))
                .attr('pointer-events', 'none')
                .attr('dx', padding)
                .attr('y', yScale.bandwidth()/2)
                .attr('dy', "0.32em")
                .text(names);

            tasks = tasks.merge(tasks_enter);

            tasks
                .attr("transform", d => translate(range[0], yScale(labels(d))))
                .selectAll('rect')
                    .attr('width', 0);

            tasks
                .transition().duration(duration)
                .attr("transform", d => translate(xScale(starts_min_width(d)), yScale(labels(d))))
                .selectAll('rect')
                    .attr('width', d => xScale(ends_min_width(d)) - xScale(starts_min_width(d)))
                .on('start', trim_text);

            if(today) 
                selection.append('path')
                    .attr('stroke', 'red')
                    .attr('d','M'+xScale(new Date)+',0.5V'+height);
            
        });
    }

    //chart.axis     = function(_) { return arguments.length? (axis  = _, chart): axis ; };
    chart.dates    = function(_) { return arguments.length? (dates = _, chart): dates; };
    chart.width    = function(_) { return arguments.length? (const_width = _, chart): const_width; };
    chart.today    = function(_) { return arguments.length? (today = _, chart): today; };
    chart.colors   = function(_) { return arguments.length? (colors = _, chart): colors; };
    chart.padding  = function(_) { return arguments.length? (padding = _, chart): padding; };
    chart.reversed = function(_) { return arguments.length? (reversed = _, chart): reversed; };
    chart.duration = function(_) { return arguments.length? (duration = _, chart): duration; };
    chart.tooltip_render  = function(_) { return arguments.length? (tooltip_render = _, chart): tooltip_render; };
    chart.min_width = function(_) { return arguments.length? (min_width = _ * 1.1, chart): min_width; };
    chart.on_item_click = function(_) { return arguments.length? (on_item_click = _, chart): on_item_click; };

    return chart;
};

exports.timeline = timeline;
exports.tooltip = tooltip;
exports.timelineAxisLeft = timelineAxisLeft;
exports.timelineAxisRight = timelineAxisRight;
exports.durationFormat = durationFormat;

Object.defineProperty(exports, '__esModule', { value: true });

})));
