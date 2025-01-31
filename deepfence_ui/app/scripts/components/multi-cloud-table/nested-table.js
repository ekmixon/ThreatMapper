import React, { useEffect } from 'react';
import { useDispatch } from 'react-redux';
import ReactTable from 'react-table';
import { showTopologyPanel } from '../../actions';
import { NODE_TYPE } from '../../constants/topology-multicloud';
import { ShimmerLoaderRow } from '../shimmer-loader/shimmer-row';
import './styles.scss';
import { addCheckbox, getColumnsForTypes } from './table-columns';

let selectedItems = [];
const RecursiveTable = ({
  data, onRowExpand, onRowCollapse, onNodeClicked, setAction, depth, metadata, parent = {}
}) => {
  if (!data || data.length === 0) {
    // check for cloud_region, if host count is 0
    // do not show shimmer loader
    const parentNodeType = parent.node_type;
    const childrenCount = metadata?.children_count || {};
    const hostCountForRegion = childrenCount[parent.id]?.hosts;
    if (parentNodeType === NODE_TYPE.REGION
      && hostCountForRegion === 0) {
      return (
        <div className="empty-row">
          No hosts found for this region.
        </div>
      );
    }
    return (
      <ShimmerLoaderRow numberOfRows={1} />
    );
  }

  const dispatch = useDispatch();
  const nodeTypes = new Set(data.map(node => node.node_type));
  const cols = getColumnsForTypes(nodeTypes, depth);
  const emptyHeaderTables = [NODE_TYPE.REGION, NODE_TYPE.KUBERNETES_CLUSTER];
  const columns = addCheckbox(cols, selectedItems, (row) => {
    if (selectedItems.indexOf(row.original.id) > -1) {
      selectedItems.splice(selectedItems.indexOf(row.original.id), 1);
    } else {
      selectedItems.push(row.original.id);
    }
    setAction(selectedItems);
  });

  const onExpandedChange = (newExpanded, index, event, cellInfo) => (newExpanded[index]
    ? onRowExpand(cellInfo.original)
    : onRowCollapse(cellInfo.original));

  const TheadComponent = () => null;
  let headerProp = {};

  nodeTypes.forEach((key) => {
    if (emptyHeaderTables.includes(key)) {
      headerProp = {
        TheadComponent
      };
    }
  });

  return (
    <ReactTable
      showPagination={false}
      // default is 20
      defaultPageSize={10000}
      showPageJump={false}
      freezeWhenExpanded={false}
      collapseOnDataChange={false}
      data={data}
      columns={columns}
      minRows={0}
      onExpandedChange={(newExpanded, index, event, cellInfo) => {
        onExpandedChange(newExpanded, index, event, cellInfo);
      }}
      getTrProps={(state, rowInfo) => (
        {
          onClick: (e) => {
            // check if clicked item is table data using it's class name
            if (e.target.className === 'rt-td') {
              dispatch(showTopologyPanel(true));
            }
            return onNodeClicked({ id: rowInfo.original.id, label: rowInfo.original.label });
          },
          style: {
            cursor: 'pointer',
          },
        }
      )}
      SubComponent={nodeTypes.has('process') ? null : row => (
        <RecursiveTable
          data={row.original.children}
          onRowExpand={onRowExpand}
          onRowCollapse={onRowCollapse}
          onNodeClicked={onNodeClicked}
          setAction={setAction}
          depth={depth + 1}
          metadata={metadata}
          parent={row.original}
        />
      )}
      {...headerProp}
    />
  );
};

export const NestedTable = ({
  data, onRowExpand, onRowCollapse, onNodeClicked, setAction, metadata
}) => {
  useEffect(() => { selectedItems = []; }, []);

  return (
    <RecursiveTable
      metadata={metadata}
      data={data}
      onRowExpand={onRowExpand}
      onRowCollapse={onRowCollapse}
      onNodeClicked={onNodeClicked}
      setAction={setAction}
      depth={1}
    />
  );
}
