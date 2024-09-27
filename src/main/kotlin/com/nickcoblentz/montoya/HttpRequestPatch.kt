package com.nickcoblentz.montoya

import burp.api.montoya.http.message.requests.HttpRequest

fun HttpRequest.pathSlices() : List<PathSlice> {
    val originalPath = this.pathWithoutQuery()

    val indices = mutableListOf<Int>()
    var index = originalPath.indexOf('/')
    while (index != -1) {
        indices.add(index)
        index = originalPath.indexOf('/', index + 1)
    }

    val pathSlices = mutableListOf<PathSlice>()

    if(indices.isNotEmpty()) {
        var previousIndex = 0
        indices.forEach {
            if(it>previousIndex) {
                pathSlices.add(PathSlice(originalPath.substring(previousIndex+1,it),previousIndex+1,it))
                previousIndex=it
            }
        }
    }

    return pathSlices
}

fun HttpRequest.replacePathSlice(pathSlice : PathSlice,replacementValue : String) : HttpRequest
{
    val newPath = this.path().replaceRange(pathSlice.startIndex,pathSlice.endIndex,replacementValue)
    return this.withPath(newPath)
}


data class PathSlice(val value : String, val startIndex : Int, val endIndex : Int)